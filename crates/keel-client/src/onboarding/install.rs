//! The install sequence, written against a small `Remote` trait so the order
//! of commands can be tested without a server.
//!
//! Every step is idempotent, so running onboarding again on a server that
//! already has the agent repairs or upgrades it in place.

use std::future::Future;
use std::time::Duration;

use keel_proto::PairingCode;
use tokio::sync::mpsc::Sender;

use super::OnboardingEvent;
use super::artifact::verify_agent_artifact;
use super::preflight::{
    Finding, FirewallKind, HostFacts, InstallOptions, Severity, firewall_rules, parse_facts,
    preflight,
};

pub const AGENT_PORT: u16 = 7443;
const AGENT_BIN: &str = "/usr/local/bin/keel-agent";
const AGENT_BIN_NEW: &str = "/usr/local/bin/keel-agent.new";
const UNIT_PATH: &str = "/etc/systemd/system/keel-agent.service";
const UNIT_FILE: &str = include_str!("../../../keel-agent/dist/keel-agent.service");
/// sshd keeps the first value it reads for a setting, and drop-ins are read
/// in name order, so ours must sort before cloud images' `50-cloud-init.conf`.
const SSHD_DROP_IN: &str = "/etc/ssh/sshd_config.d/01-keel.conf";
/// Where earlier versions wrote the drop-in.
const SSHD_DROP_IN_OLD: &str = "/etc/ssh/sshd_config.d/50-keel.conf";
const AUTO_UPGRADES_PATH: &str = "/etc/apt/apt.conf.d/20auto-upgrades";
const AUTO_UPGRADES: &str =
    "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n";
/// How long the agent gets to start listening.
pub const AGENT_START_WAIT: Duration = Duration::from_secs(15);

/// (exit code, stdout, stderr)
pub type ExecOutput = (i32, String, String);

/// A shell on the server.
pub trait Remote {
    /// Run `cmd` through the login shell, feeding `stdin` if given.
    fn exec(
        &mut self,
        cmd: &str,
        stdin: Option<&[u8]>,
    ) -> impl Future<Output = anyhow::Result<ExecOutput>> + Send;

    /// Whether a TCP connection to `port` on the server succeeds within `within`.
    fn reachable(&mut self, port: u16, within: Duration) -> impl Future<Output = bool> + Send;
}

/// Signed agent binaries, one per processor architecture.
#[derive(Clone, Default)]
pub struct AgentArtifacts {
    pub x86_64: Option<(Vec<u8>, [u8; 64])>,
    pub aarch64: Option<(Vec<u8>, [u8; 64])>,
}

impl std::fmt::Debug for AgentArtifacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentArtifacts")
            .field("x86_64", &self.x86_64.as_ref().map(|(b, _)| b.len()))
            .field("aarch64", &self.aarch64.as_ref().map(|(b, _)| b.len()))
            .finish()
    }
}

impl AgentArtifacts {
    fn for_arch(&self, arch: &str) -> Option<&(Vec<u8>, [u8; 64])> {
        match arch {
            "x86_64" => self.x86_64.as_ref(),
            "aarch64" => self.aarch64.as_ref(),
            _ => None,
        }
    }
}

/// A failed step, already worded for the person: `"<Step>: <explanation>"`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct StepFailed(pub String);

/// What the install sequence needs besides the server itself.
pub struct Plan<'a> {
    /// The address the desktop used; the agent advertises it.
    pub host: &'a str,
    pub ssh_port: u16,
    pub opts: &'a InstallOptions,
    /// The SSH session signed in with a key (not a password).
    pub key_auth: bool,
    pub artifacts: &'a AgentArtifacts,
    pub pubkey: &'a [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    pub facts: HostFacts,
    pub fingerprint: String,
    pub token: String,
}

/// Quote `s` for a POSIX shell.
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn is_debian_family(f: &HostFacts) -> bool {
    matches!(f.os_id.as_str(), "ubuntu" | "debian")
}

fn is_rhel_family(f: &HostFacts) -> bool {
    matches!(f.os_id.as_str(), "almalinux" | "rocky" | "ol")
}

async fn emit(events: &Sender<OnboardingEvent>, ev: OnboardingEvent) {
    // The receiver going away (window closed) must not stop the install halfway.
    let _ = events.send(ev).await;
}

struct Runner<'r, R: Remote> {
    remote: &'r mut R,
    is_root: bool,
}

impl<R: Remote> Runner<'_, R> {
    /// Run unprivileged; transport failures become a step failure.
    async fn read(&mut self, step: &str, cmd: &str) -> Result<ExecOutput, StepFailed> {
        self.remote.exec(cmd, None).await.map_err(|e| {
            tracing::debug!(error = %e, cmd, "ssh exec failed");
            StepFailed(format!(
                "{step}: The connection to the server was lost. Check your connection and try again."
            ))
        })
    }

    /// Run with root privileges (`sudo -n` unless already root), returning the
    /// raw result.
    async fn try_root(
        &mut self,
        step: &str,
        cmd: &str,
        stdin: Option<&[u8]>,
    ) -> Result<ExecOutput, StepFailed> {
        let full = if self.is_root {
            cmd.to_string()
        } else {
            format!("sudo -n {cmd}")
        };
        self.remote.exec(&full, stdin).await.map_err(|e| {
            tracing::debug!(error = %e, cmd = full, "ssh exec failed");
            StepFailed(format!(
                "{step}: The connection to the server was lost. Check your connection and try again."
            ))
        })
    }

    /// Run with root privileges; a non-zero exit fails the step with `why`.
    async fn root(
        &mut self,
        step: &str,
        why: &str,
        cmd: &str,
        stdin: Option<&[u8]>,
    ) -> Result<String, StepFailed> {
        let (code, out, err) = self.try_root(step, cmd, stdin).await?;
        if code != 0 {
            tracing::debug!(step, cmd, code, stderr = %err, "remote command failed");
            return Err(StepFailed(format!("{step}: {why}")));
        }
        Ok(out)
    }

    /// Run as the `keel` user.
    async fn as_keel(&mut self, step: &str, why: &str, cmd: &str) -> Result<String, StepFailed> {
        self.root(step, why, &format!("runuser -u keel -- {cmd}"), None)
            .await
    }

    /// Write `content` to `path` as root.
    async fn write_file(
        &mut self,
        step: &str,
        why: &str,
        path: &str,
        content: &[u8],
    ) -> Result<(), StepFailed> {
        let cmd = format!("sh -c {}", shell_quote(&format!("cat > {path}")));
        self.root(step, why, &cmd, Some(content)).await.map(|_| ())
    }
}

/// Gather facts with read-only commands. Returns the facts (with the agent's
/// own port removed when the agent is already running) and the port the SSH
/// server sees this session on, if it reports one.
async fn gather_facts<R: Remote>(
    run: &mut Runner<'_, R>,
    ssh_port: u16,
) -> Result<(HostFacts, Option<u16>), StepFailed> {
    const STEP: &str = "Checking the server";
    let os_release = run.read(STEP, "cat /etc/os-release").await?.1;
    let uname = run.read(STEP, "uname -m").await?.1;
    let systemd = run.read(STEP, "systemctl --version").await?.0 == 0;
    let df = run.read(STEP, "df -B1 --output=avail /").await?.1;
    let ss = run.read(STEP, "ss -Htln").await?.1;
    let id_u = run.read(STEP, "id -u").await?.1;
    let is_root = id_u.trim() == "0";
    let sudo_ok = !is_root && run.read(STEP, "sudo -n true").await?.0 == 0;
    let fw = if run.read(STEP, "command -v ufw").await?.0 == 0 {
        FirewallKind::Ufw
    } else if run.read(STEP, "command -v firewall-cmd").await?.0 == 0 {
        FirewallKind::Firewalld
    } else {
        FirewallKind::None
    };
    let mut facts = parse_facts(
        &os_release,
        &uname,
        systemd,
        &df,
        &ss,
        ssh_port,
        &id_u,
        sudo_ok,
        fw,
    );
    run.is_root = facts.is_root;

    // Re-onboarding: our own agent holding its port is not a conflict.
    if run
        .read(STEP, "systemctl is-active --quiet keel-agent")
        .await?
        .0
        == 0
    {
        facts.ports_in_use.retain(|p| *p != AGENT_PORT);
    }

    // "client_ip client_port server_ip server_port": the port sshd really
    // listens on, which differs from ours behind port forwarding.
    let (code, out, _) = run.read(STEP, "printenv SSH_CONNECTION").await?;
    let seen_port = (code == 0)
        .then(|| out.split_whitespace().nth(3)?.parse::<u16>().ok())
        .flatten();
    Ok((facts, seen_port))
}

/// Steps 1 to 8: check the server, then install and configure the agent.
/// Nothing is written to the server unless the checks pass.
pub async fn install<R: Remote + Send>(
    remote: &mut R,
    plan: &Plan<'_>,
    events: &Sender<OnboardingEvent>,
) -> Result<Installed, StepFailed> {
    let mut run = Runner {
        remote,
        is_root: false,
    };

    // 1. Check. Read-only.
    emit(events, OnboardingEvent::Checking).await;
    let (facts, seen_ssh_port) = gather_facts(&mut run, plan.ssh_port).await?;
    let findings = preflight(&facts, AGENT_PORT);
    if !findings.is_empty() {
        emit(events, OnboardingEvent::Findings(findings.clone())).await;
    }
    let blockers: Vec<&str> = findings
        .iter()
        .filter(|f| f.severity == Severity::Blocker)
        .map(|f| f.message.as_str())
        .collect();
    if !blockers.is_empty() {
        return Err(StepFailed(blockers.join(" ")));
    }

    // 2. Choose and verify the agent before touching the server.
    let Some((bin, sig)) = plan.artifacts.for_arch(&facts.arch) else {
        return Err(StepFailed(format!(
            "This app doesn't include the agent for {} servers.",
            facts.arch
        )));
    };
    verify_agent_artifact(bin, sig, plan.pubkey)
        .map_err(|e| StepFailed(format!("Checking the agent: {e}")))?;

    // 3. Upload: write beside the target, check it arrived intact, then
    // rename over the old binary so a running agent never sees a partial file.
    const UPLOAD: &str = "Uploading the agent";
    emit(events, OnboardingEvent::Installing(UPLOAD)).await;
    let no_space =
        "The server couldn't save the agent program. Check there's free disk space and try again.";
    run.write_file(UPLOAD, no_space, AGENT_BIN_NEW, bin).await?;
    let sum = run
        .root(
            UPLOAD,
            no_space,
            &format!("sha256sum {AGENT_BIN_NEW}"),
            None,
        )
        .await?;
    let want = hex::encode(ring::digest::digest(&ring::digest::SHA256, bin));
    if sum.split_whitespace().next() != Some(want.as_str()) {
        run.try_root(UPLOAD, &format!("rm -f {AGENT_BIN_NEW}"), None)
            .await?;
        return Err(StepFailed(format!(
            "{UPLOAD}: The agent program was damaged on the way to the server. Try again."
        )));
    }
    run.root(
        UPLOAD,
        no_space,
        &format!("chmod 755 {AGENT_BIN_NEW}"),
        None,
    )
    .await?;
    run.root(
        UPLOAD,
        "The server couldn't put the agent program in place. Try again.",
        &format!("mv -f {AGENT_BIN_NEW} {AGENT_BIN}"),
        None,
    )
    .await?;

    // 4. User, directories and service.
    const SETUP: &str = "Setting up the agent";
    emit(events, OnboardingEvent::Installing(SETUP)).await;
    if run.try_root(SETUP, "id keel", None).await?.0 != 0 {
        run.root(
            SETUP,
            "Couldn't create the keel system user.",
            "useradd --system --no-create-home --home-dir /var/lib/keel --shell /usr/sbin/nologin keel",
            None,
        )
        .await?;
    }
    let dirs = "Couldn't create the agent's folders.";
    run.root(
        SETUP,
        dirs,
        "install -d -m 0700 -o keel -g keel /var/lib/keel",
        None,
    )
    .await?;
    // A recreated keel user can have a new uid; files left from the old one
    // would stop `init` from writing its TLS identity.
    run.root(SETUP, dirs, "chown -R keel:keel /var/lib/keel", None)
        .await?;
    run.root(SETUP, dirs, "install -d -m 0755 /etc/keel", None)
        .await?;
    run.write_file(
        SETUP,
        "Couldn't install the agent's system service.",
        UNIT_PATH,
        UNIT_FILE.as_bytes(),
    )
    .await?;
    run.root(
        SETUP,
        "systemd couldn't load the agent's service.",
        "systemctl daemon-reload",
        None,
    )
    .await?;

    // 5. Identity and a fresh one-time pairing token.
    let init_out = run
        .as_keel(
            SETUP,
            "The agent couldn't set itself up. Check the agent logs with: journalctl -u keel-agent",
            &format!("{AGENT_BIN} init --host {}", shell_quote(plan.host)),
        )
        .await?;
    let (fingerprint, token) = parse_init(&init_out).ok_or_else(|| {
        StepFailed(format!(
            "{SETUP}: The agent's setup output wasn't understood. Make sure the app and agent versions match."
        ))
    })?;

    // 6. Start (restart picks up a new binary on re-onboarding).
    const START: &str = "Starting the agent";
    emit(events, OnboardingEvent::Installing(START)).await;
    let wont_start =
        "The agent's service wouldn't start. Check the agent logs with: journalctl -u keel-agent";
    run.root(START, wont_start, "systemctl enable keel-agent", None)
        .await?;
    run.root(START, wont_start, "systemctl restart keel-agent", None)
        .await?;

    // 7. Firewall.
    if plan.opts.enable_firewall {
        firewall(&mut run, &facts, seen_ssh_port, events).await?;
    }

    // 8. Hardening.
    if plan.opts.auto_security_updates {
        security_updates(&mut run, &facts, events).await?;
    }
    if plan.opts.disable_ssh_passwords {
        if plan.key_auth {
            disable_ssh_passwords(&mut run, events).await?;
        } else {
            emit(
                events,
                OnboardingEvent::Findings(vec![Finding {
                    severity: Severity::Warning,
                    message: "SSH password sign-in was left on, because you signed in with a password. Turning it off now could lock you out.".into(),
                }]),
            )
            .await;
        }
    }

    // The agent should be listening by now; give it a little longer if not.
    if !run.remote.reachable(AGENT_PORT, AGENT_START_WAIT).await {
        return Err(StepFailed(format!(
            "{START}: The agent started but Keel can't reach port {AGENT_PORT}. Allow it in your server's firewall and your hosting provider's firewall, then try again."
        )));
    }

    Ok(Installed {
        facts,
        fingerprint,
        token,
    })
}

/// Parse `fingerprint=` and `pairing_code=` lines; both must agree.
pub fn parse_init(out: &str) -> Option<(String, String)> {
    let line = |key: &str| {
        out.lines()
            .find_map(|l| l.trim().strip_prefix(key).map(str::to_string))
    };
    let fingerprint = line("fingerprint=")?;
    let code = PairingCode::parse(&line("pairing_code=")?).ok()?;
    if fingerprint.is_empty() || code.fingerprint != fingerprint || code.token.is_empty() {
        return None;
    }
    Some((fingerprint, code.token))
}

async fn firewall<R: Remote>(
    run: &mut Runner<'_, R>,
    facts: &HostFacts,
    seen_ssh_port: Option<u16>,
    events: &Sender<OnboardingEvent>,
) -> Result<(), StepFailed> {
    const STEP: &str = "Setting up the firewall";
    // Allow every port this session could be using, so enabling the firewall
    // never cuts off SSH.
    let mut ports = firewall_rules(facts, AGENT_PORT);
    if let Some(p) = seen_ssh_port
        && !ports.contains(&p)
    {
        ports.insert(0, p);
    }
    let mut kind = facts.firewall;
    if kind == FirewallKind::None {
        if is_debian_family(facts) {
            emit(events, OnboardingEvent::Installing(STEP)).await;
            apt_install(run, STEP, "ufw").await?;
            kind = FirewallKind::Ufw;
        } else {
            emit(
                events,
                OnboardingEvent::Findings(vec![Finding {
                    severity: Severity::Warning,
                    message: "No firewall is installed on this server, so Keel didn't set one up."
                        .into(),
                }]),
            )
            .await;
            return Ok(());
        }
    } else {
        emit(events, OnboardingEvent::Installing(STEP)).await;
    }
    let refused = "The firewall refused a rule change. Check its settings and try again.";
    match kind {
        FirewallKind::Ufw => {
            for p in &ports {
                run.root(STEP, refused, &format!("ufw allow {p}/tcp"), None)
                    .await?;
            }
            run.root(STEP, refused, "ufw --force enable", None).await?;
        }
        FirewallKind::Firewalld => {
            if run.try_root(STEP, "firewall-cmd --state", None).await?.0 != 0 {
                emit(
                    events,
                    OnboardingEvent::Findings(vec![Finding {
                        severity: Severity::Warning,
                        message: "firewalld is installed but not running, so Keel didn't change the firewall.".into(),
                    }]),
                )
                .await;
                return Ok(());
            }
            for p in &ports {
                run.root(
                    STEP,
                    refused,
                    &format!("firewall-cmd --permanent --add-port={p}/tcp"),
                    None,
                )
                .await?;
            }
            run.root(STEP, refused, "firewall-cmd --reload", None)
                .await?;
        }
        FirewallKind::None => {}
    }
    Ok(())
}

async fn apt_install<R: Remote>(
    run: &mut Runner<'_, R>,
    step: &str,
    package: &str,
) -> Result<(), StepFailed> {
    let why = format!(
        "Couldn't install {package}. Check the server can reach its package mirrors and try again."
    );
    // Fresh images often ship without package lists.
    run.root(
        step,
        &why,
        "env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 update -q",
        None,
    )
    .await?;
    run.root(
        step,
        &why,
        &format!(
            "env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 install -y {package}"
        ),
        None,
    )
    .await
    .map(|_| ())
}

async fn security_updates<R: Remote>(
    run: &mut Runner<'_, R>,
    facts: &HostFacts,
    events: &Sender<OnboardingEvent>,
) -> Result<(), StepFailed> {
    const STEP: &str = "Turning on security updates";
    if is_debian_family(facts) {
        emit(events, OnboardingEvent::Installing(STEP)).await;
        apt_install(run, STEP, "unattended-upgrades").await?;
        run.write_file(
            STEP,
            "Couldn't turn on automatic updates.",
            AUTO_UPGRADES_PATH,
            AUTO_UPGRADES.as_bytes(),
        )
        .await?;
    } else if is_rhel_family(facts) {
        emit(events, OnboardingEvent::Installing(STEP)).await;
        // dnf can take many minutes on small instances (it loads large repo
        // metadata), long enough for the SSH session to drop. Run it as a
        // transient systemd unit on the server so the session returns at once.
        let (code, _, _) = run
            .try_root(
                STEP,
                &format!(
                    "systemd-run --collect sh -c {}",
                    shell_quote(
                        "dnf install -y dnf-automatic && systemctl enable --now dnf-automatic.timer"
                    )
                ),
                None,
            )
            .await?;
        if code != 0 {
            emit(
                events,
                OnboardingEvent::Findings(vec![Finding {
                    severity: Severity::Warning,
                    message: SECURITY_UPDATES_SKIPPED.into(),
                }]),
            )
            .await;
        }
    }
    Ok(())
}

pub(crate) const SECURITY_UPDATES_SKIPPED: &str = "Keel couldn't turn on automatic security updates. You can turn them on later with: sudo dnf install -y dnf-automatic && sudo systemctl enable --now dnf-automatic.timer";

async fn disable_ssh_passwords<R: Remote>(
    run: &mut Runner<'_, R>,
    events: &Sender<OnboardingEvent>,
) -> Result<(), StepFailed> {
    const STEP: &str = "Turning off SSH passwords";
    emit(events, OnboardingEvent::Installing(STEP)).await;
    let warn = |message: &str| {
        OnboardingEvent::Findings(vec![Finding {
            severity: Severity::Warning,
            message: message.into(),
        }])
    };
    // If the existing configuration is already broken, any reload could
    // fail; leave every file as it is.
    if run.try_root(STEP, "sshd -t", None).await?.0 != 0 {
        emit(
            events,
            warn("Your current SSH configuration has errors, so Keel left it unchanged."),
        )
        .await;
        return Ok(());
    }
    let why = "Couldn't change the SSH settings.";
    run.root(STEP, why, "install -d -m 0755 /etc/ssh/sshd_config.d", None)
        .await?;
    run.write_file(STEP, why, SSHD_DROP_IN, b"PasswordAuthentication no\n")
        .await?;
    run.root(STEP, why, &format!("rm -f {SSHD_DROP_IN_OLD}"), None)
        .await?;
    // Never reload sshd with a config it rejects.
    if run.try_root(STEP, "sshd -t", None).await?.0 != 0 {
        run.try_root(STEP, &format!("rm -f {SSHD_DROP_IN}"), None)
            .await?;
        return Err(StepFailed(format!(
            "{STEP}: The SSH server rejected the change, so it was undone. Your SSH settings are unchanged."
        )));
    }
    run.root(
        STEP,
        "Couldn't reload the SSH server. The change applies after its next restart.",
        &format!(
            "sh -c {}",
            shell_quote("systemctl reload ssh || systemctl reload sshd")
        ),
        None,
    )
    .await?;
    // Confirm the setting sshd actually uses.
    let (code, out, _) = run.try_root(STEP, "sshd -T", None).await?;
    let off = code == 0
        && out
            .lines()
            .any(|l| l.trim().eq_ignore_ascii_case("passwordauthentication no"));
    if !off {
        emit(
            events,
            warn("SSH password sign-in is still on: Another SSH configuration file on this server overrides Keel's setting. Look for PasswordAuthentication in /etc/ssh/sshd_config and /etc/ssh/sshd_config.d/."),
        )
        .await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use tokio::sync::mpsc;

    const UBUNTU: &str = "PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nVERSION_ID=\"24.04\"\nID=ubuntu\n";
    const ROCKY: &str = "ID=\"rocky\"\nVERSION_ID=\"9.4\"\nPRETTY_NAME=\"Rocky Linux 9.4\"\n";
    const FP: &str = "ab12cd";

    /// Commands that only read; everything else counts as a change.
    const READ_ONLY: &[&str] = &[
        "cat /etc/os-release",
        "uname -m",
        "systemctl --version",
        "df -B1 --output=avail /",
        "ss -Htln",
        "id -u",
        "sudo -n true",
        "command -v ufw",
        "command -v firewall-cmd",
        "systemctl is-active --quiet keel-agent",
        "printenv SSH_CONNECTION",
    ];

    struct Fake {
        /// (command prefix, exit, stdout); first match wins, default success.
        rules: Vec<(String, i32, String)>,
        log: Vec<(String, Option<Vec<u8>>)>,
        reachable: bool,
        /// The first `sshd -t` succeeds regardless of rules.
        sshd_t_ok_first: bool,
    }

    impl Fake {
        fn server(os: &str, ss: &str, uid: &str) -> Fake {
            let code = PairingCode {
                host: "h".into(),
                port: AGENT_PORT,
                fingerprint: FP.into(),
                token: "tok".into(),
            };
            let mut f = Fake {
                rules: Vec::new(),
                log: Vec::new(),
                reachable: true,
                sshd_t_ok_first: false,
            };
            f.on("cat /etc/os-release", 0, os)
                .on("uname -m", 0, "x86_64\n")
                .on("df -B1", 0, "Avail\n21474836480\n")
                .on("ss -Htln", 0, ss)
                .on("id -u", 0, uid)
                .on("command -v ufw", 0, "/usr/sbin/ufw\n")
                .on("systemctl is-active", 3, "")
                .on("printenv SSH_CONNECTION", 0, "10.0.0.9 50000 10.0.0.1 22\n")
                .on("sshd -T", 0, "port 22\npasswordauthentication no\n")
                .on(
                    "runuser",
                    0,
                    &format!("fingerprint={FP}\npairing_code={}\n", code.encode()),
                )
                .on(
                    "sudo -n runuser",
                    0,
                    &format!("fingerprint={FP}\npairing_code={}\n", code.encode()),
                );
            f
        }

        fn on(&mut self, prefix: &str, code: i32, out: &str) -> &mut Fake {
            self.rules.insert(0, (prefix.into(), code, out.into()));
            self
        }

        fn cmds(&self) -> Vec<&str> {
            self.log.iter().map(|(c, _)| c.as_str()).collect()
        }

        fn writes(&self) -> Vec<&str> {
            self.cmds()
                .into_iter()
                .filter(|c| !READ_ONLY.contains(c))
                .collect()
        }
    }

    impl Remote for Fake {
        async fn exec(&mut self, cmd: &str, stdin: Option<&[u8]>) -> anyhow::Result<ExecOutput> {
            self.log.push((cmd.to_string(), stdin.map(<[u8]>::to_vec)));
            if cmd == "sshd -t" && self.sshd_t_ok_first {
                self.sshd_t_ok_first = false;
                return Ok((0, String::new(), String::new()));
            }
            if cmd.contains("sha256sum") {
                let bin = self
                    .log
                    .iter()
                    .rev()
                    .find_map(|(c, s)| c.contains(AGENT_BIN_NEW).then(|| s.clone()).flatten())
                    .unwrap_or_default();
                let h = hex::encode(ring::digest::digest(&ring::digest::SHA256, &bin));
                return Ok((0, format!("{h}  {AGENT_BIN_NEW}\n"), String::new()));
            }
            let (code, out) = self
                .rules
                .iter()
                .find(|(p, _, _)| cmd.starts_with(p.as_str()))
                .map(|(_, c, o)| (*c, o.clone()))
                .unwrap_or((0, String::new()));
            Ok((
                code,
                out,
                if code == 0 {
                    String::new()
                } else {
                    "boom".into()
                },
            ))
        }

        async fn reachable(&mut self, _port: u16, _within: Duration) -> bool {
            self.reachable
        }
    }

    struct Keys {
        artifacts: AgentArtifacts,
        pubkey: [u8; 32],
    }

    fn keys() -> Keys {
        let kp = Ed25519KeyPair::from_seed_unchecked(&[3; 32]).unwrap();
        let bin = b"\x7fELF agent".to_vec();
        let sig: [u8; 64] = kp.sign(&bin).as_ref().try_into().unwrap();
        Keys {
            artifacts: AgentArtifacts {
                x86_64: Some((bin, sig)),
                aarch64: None,
            },
            pubkey: kp.public_key().as_ref().try_into().unwrap(),
        }
    }

    async fn go(
        fake: &mut Fake,
        opts: InstallOptions,
        key_auth: bool,
        ssh_port: u16,
        keys: &Keys,
    ) -> (Result<Installed, StepFailed>, Vec<OnboardingEvent>) {
        let (tx, mut rx) = mpsc::channel(256);
        let plan = Plan {
            host: "203.0.113.5",
            ssh_port,
            opts: &opts,
            key_auth,
            artifacts: &keys.artifacts,
            pubkey: &keys.pubkey,
        };
        let r = install(fake, &plan, &tx).await;
        drop(tx);
        let mut evs = Vec::new();
        while let Some(e) = rx.recv().await {
            evs.push(e);
        }
        (r, evs)
    }

    fn opts(firewall: bool, updates: bool, no_passwords: bool) -> InstallOptions {
        InstallOptions {
            enable_firewall: firewall,
            auto_security_updates: updates,
            disable_ssh_passwords: no_passwords,
            keep_ssh_credentials: false,
        }
    }

    #[tokio::test]
    async fn blocker_issues_zero_write_commands() {
        let mut fake = Fake::server(UBUNTU, "LISTEN 0 1 0.0.0.0:7443 0.0.0.0:*\n", "0\n");
        let (r, evs) = go(&mut fake, opts(true, true, true), true, 22, &keys()).await;
        assert_eq!(
            r.unwrap_err().0,
            "Port 7443 is already in use on this server. Keel's agent needs it."
        );
        assert!(fake.writes().is_empty(), "wrote: {:?}", fake.writes());
        assert!(
            evs.iter()
                .any(|e| matches!(e, OnboardingEvent::Findings(_)))
        );
        assert!(
            !evs.iter()
                .any(|e| matches!(e, OnboardingEvent::Installing(_)))
        );
    }

    #[tokio::test]
    async fn unsupported_os_and_no_sudo_block_without_writes() {
        let mut fake = Fake::server("ID=centos\nVERSION_ID=\"7\"\n", "", "1000\n");
        fake.on("sudo -n true", 1, "");
        let (r, _) = go(&mut fake, opts(true, true, false), true, 22, &keys()).await;
        let msg = r.unwrap_err().0;
        assert!(msg.contains("isn't supported"), "{msg}");
        assert!(msg.contains("passwordless sudo"), "{msg}");
        assert!(fake.writes().is_empty(), "wrote: {:?}", fake.writes());
    }

    #[tokio::test]
    async fn bad_signature_or_missing_arch_writes_nothing() {
        let mut k = keys();
        k.artifacts.x86_64.as_mut().unwrap().1[0] ^= 1;
        let mut fake = Fake::server(UBUNTU, "", "0\n");
        let (r, _) = go(&mut fake, opts(true, true, false), true, 22, &k).await;
        assert!(r.unwrap_err().0.contains("signature check"));
        assert!(fake.writes().is_empty(), "wrote: {:?}", fake.writes());

        let mut fake = Fake::server(UBUNTU, "", "0\n");
        fake.on("uname -m", 0, "aarch64\n");
        let (r, _) = go(&mut fake, opts(true, true, false), true, 22, &keys()).await;
        assert_eq!(
            r.unwrap_err().0,
            "This app doesn't include the agent for aarch64 servers."
        );
        assert!(fake.writes().is_empty());
    }

    #[tokio::test]
    async fn already_active_agent_port_not_busy() {
        let mut fake = Fake::server(UBUNTU, "LISTEN 0 1 0.0.0.0:7443 0.0.0.0:*\n", "0\n");
        fake.on("systemctl is-active", 0, "");
        let (r, _) = go(&mut fake, opts(false, false, false), true, 22, &keys()).await;
        let installed = r.unwrap();
        assert!(!installed.facts.ports_in_use.contains(&7443));
        assert_eq!(installed.fingerprint, FP);
        assert_eq!(installed.token, "tok");
        assert!(fake.cmds().contains(&"systemctl restart keel-agent"));
    }

    #[tokio::test]
    async fn full_sequence_in_order_as_root() {
        let mut fake = Fake::server(UBUNTU, "", "0\n");
        let (r, _) = go(&mut fake, opts(true, false, false), true, 22, &keys()).await;
        r.unwrap();
        let w = fake.writes();
        let pos = |c: &str| {
            w.iter()
                .position(|x| x.starts_with(c))
                .unwrap_or_else(|| panic!("{c} not run: {w:?}"))
        };
        let order = [
            "sh -c 'cat > /usr/local/bin/keel-agent.new'",
            "sha256sum /usr/local/bin/keel-agent.new",
            "chmod 755 /usr/local/bin/keel-agent.new",
            "mv -f /usr/local/bin/keel-agent.new /usr/local/bin/keel-agent",
            "id keel",
            "install -d -m 0700 -o keel -g keel /var/lib/keel",
            "chown -R keel:keel /var/lib/keel",
            "install -d -m 0755 /etc/keel",
            "sh -c 'cat > /etc/systemd/system/keel-agent.service'",
            "systemctl daemon-reload",
            "runuser -u keel -- /usr/local/bin/keel-agent init --host '203.0.113.5'",
            "systemctl enable keel-agent",
            "systemctl restart keel-agent",
            "ufw allow 22/tcp",
            "ufw --force enable",
        ];
        for pair in order.windows(2) {
            assert!(
                pos(pair[0]) < pos(pair[1]),
                "{} before {}",
                pair[0],
                pair[1]
            );
        }
        assert!(
            !w.iter().any(|c| c.starts_with("sudo")),
            "root needs no sudo"
        );
        // `keel` exists by default in the fake, so no useradd.
        assert!(!w.iter().any(|c| c.starts_with("useradd")));
        let unit = fake
            .log
            .iter()
            .find(|(c, _)| c.contains(UNIT_PATH))
            .and_then(|(_, s)| s.clone())
            .unwrap();
        assert_eq!(unit, UNIT_FILE.as_bytes());
        let bin = fake
            .log
            .iter()
            .find(|(c, _)| c.contains(AGENT_BIN_NEW))
            .and_then(|(_, s)| s.clone())
            .unwrap();
        assert_eq!(bin, keys().artifacts.x86_64.unwrap().0);
    }

    #[tokio::test]
    async fn non_root_prefixes_sudo_and_creates_user() {
        let mut fake = Fake::server(UBUNTU, "", "1000\n");
        fake.on("sudo -n id keel", 1, "");
        let (r, _) = go(&mut fake, opts(false, false, false), true, 22, &keys()).await;
        r.unwrap();
        let w = fake.writes();
        assert!(w.iter().all(|c| c.starts_with("sudo -n ")), "{w:?}");
        assert!(w.contains(
            &"sudo -n useradd --system --no-create-home --home-dir /var/lib/keel --shell /usr/sbin/nologin keel"
        ));
        assert!(w.contains(
            &"sudo -n runuser -u keel -- /usr/local/bin/keel-agent init --host '203.0.113.5'"
        ));
    }

    #[tokio::test]
    async fn firewall_rules_include_nonstandard_ssh_port() {
        let mut fake = Fake::server(UBUNTU, "", "0\n");
        fake.on(
            "printenv SSH_CONNECTION",
            0,
            "10.0.0.9 50000 10.0.0.1 2222\n",
        );
        let (r, _) = go(&mut fake, opts(true, false, false), true, 2222, &keys()).await;
        r.unwrap();
        let ufw: Vec<&str> = fake
            .cmds()
            .into_iter()
            .filter(|c| c.starts_with("ufw"))
            .collect();
        assert_eq!(
            ufw,
            [
                "ufw allow 2222/tcp",
                "ufw allow 80/tcp",
                "ufw allow 443/tcp",
                "ufw allow 7443/tcp",
                "ufw --force enable"
            ]
        );
    }

    #[tokio::test]
    async fn firewall_keeps_server_side_ssh_port_behind_forwarding() {
        // Desktop connects to 2222, which a NAT forwards to sshd on 22.
        let mut fake = Fake::server(UBUNTU, "", "0\n");
        let (r, _) = go(&mut fake, opts(true, false, false), true, 2222, &keys()).await;
        r.unwrap();
        let cmds = fake.cmds();
        assert!(cmds.contains(&"ufw allow 22/tcp"));
        assert!(cmds.contains(&"ufw allow 2222/tcp"));
        let enable = cmds
            .iter()
            .position(|c| *c == "ufw --force enable")
            .unwrap();
        let allow22 = cmds.iter().position(|c| *c == "ufw allow 22/tcp").unwrap();
        assert!(allow22 < enable);
    }

    #[tokio::test]
    async fn firewalld_and_no_firewall_on_rhel() {
        let mut fake = Fake::server(ROCKY, "", "0\n");
        fake.on("command -v ufw", 1, "").on(
            "command -v firewall-cmd",
            0,
            "/usr/bin/firewall-cmd\n",
        );
        let (r, _) = go(&mut fake, opts(true, true, false), true, 22, &keys()).await;
        r.unwrap();
        let cmds = fake.cmds();
        assert!(cmds.contains(&"firewall-cmd --permanent --add-port=22/tcp"));
        assert!(cmds.contains(&"firewall-cmd --permanent --add-port=7443/tcp"));
        assert!(cmds.contains(&"firewall-cmd --reload"));
        assert!(cmds.contains(
            &"systemd-run --collect sh -c 'dnf install -y dnf-automatic && systemctl enable --now dnf-automatic.timer'"
        ));

        let mut fake = Fake::server(ROCKY, "", "0\n");
        fake.on("command -v ufw", 1, "")
            .on("command -v firewall-cmd", 1, "");
        let (r, evs) = go(&mut fake, opts(true, false, false), true, 22, &keys()).await;
        r.unwrap();
        assert!(
            !fake
                .cmds()
                .iter()
                .any(|c| c.contains("ufw") && !c.starts_with("command"))
        );
        assert!(evs.iter().any(|e| matches!(e, OnboardingEvent::Findings(f)
            if f[0].severity == Severity::Warning && f[0].message.contains("No firewall"))));
    }

    #[tokio::test]
    async fn oracle_linux_uses_firewalld_and_dnf_automatic() {
        const ORACLE: &str =
            "ID=\"ol\"\nVERSION_ID=\"9.8\"\nPRETTY_NAME=\"Oracle Linux Server 9.8\"\n";
        let mut fake = Fake::server(ORACLE, "", "0\n");
        fake.on("command -v ufw", 1, "").on(
            "command -v firewall-cmd",
            0,
            "/usr/bin/firewall-cmd\n",
        );
        let (r, _) = go(&mut fake, opts(true, true, false), true, 22, &keys()).await;
        r.unwrap();
        let cmds = fake.cmds();
        assert!(cmds.contains(&"firewall-cmd --permanent --add-port=7443/tcp"));
        assert!(cmds.contains(
            &"systemd-run --collect sh -c 'dnf install -y dnf-automatic && systemctl enable --now dnf-automatic.timer'"
        ));
    }

    #[tokio::test]
    async fn rhel_security_updates_failure_is_only_a_warning() {
        let mut fake = Fake::server(ROCKY, "", "0\n");
        fake.on("command -v ufw", 1, "")
            .on("command -v firewall-cmd", 1, "")
            .on("systemd-run", 1, "");
        let (r, evs) = go(&mut fake, opts(false, true, false), true, 22, &keys()).await;
        r.unwrap();
        assert!(evs.iter().any(|e| matches!(e, OnboardingEvent::Findings(f)
            if f[0].severity == Severity::Warning
                && f[0].message == SECURITY_UPDATES_SKIPPED)));
    }

    #[tokio::test]
    async fn debian_without_firewall_installs_ufw_and_updates() {
        let mut fake = Fake::server(UBUNTU, "", "0\n");
        fake.on("command -v ufw", 1, "")
            .on("command -v firewall-cmd", 1, "");
        let (r, _) = go(&mut fake, opts(true, true, false), true, 22, &keys()).await;
        r.unwrap();
        let cmds = fake.cmds();
        let ufw_install = cmds
            .iter()
            .position(|c| c.ends_with("install -y ufw"))
            .unwrap();
        let first_allow = cmds
            .iter()
            .position(|c| c.starts_with("ufw allow"))
            .unwrap();
        assert!(ufw_install < first_allow);
        assert!(cmds.iter().any(
            |c| c.starts_with("env DEBIAN_FRONTEND=noninteractive apt-get")
                && c.ends_with("install -y unattended-upgrades")
        ));
        assert!(cmds.iter().any(|c| c.contains(AUTO_UPGRADES_PATH)));
    }

    #[tokio::test]
    async fn password_auth_never_writes_sshd_drop_in() {
        let mut fake = Fake::server(UBUNTU, "", "0\n");
        let (r, evs) = go(&mut fake, opts(false, false, true), false, 22, &keys()).await;
        r.unwrap();
        assert!(
            !fake.cmds().iter().any(|c| c.contains("sshd")),
            "{:?}",
            fake.cmds()
        );
        assert!(evs.iter().any(|e| matches!(e, OnboardingEvent::Findings(f)
            if f[0].message.contains("password sign-in was left on"))));
    }

    #[tokio::test]
    async fn key_auth_writes_validated_drop_in() {
        let mut fake = Fake::server(UBUNTU, "", "0\n");
        let (r, _) = go(&mut fake, opts(false, false, true), true, 22, &keys()).await;
        r.unwrap();
        let cmds = fake.cmds();
        let pre = cmds.iter().position(|c| *c == "sshd -t").unwrap();
        let write = cmds
            .iter()
            .position(|c| c.contains("cat > /etc/ssh/sshd_config.d/01-keel.conf"))
            .unwrap();
        let old = cmds
            .iter()
            .position(|c| *c == "rm -f /etc/ssh/sshd_config.d/50-keel.conf")
            .unwrap();
        let test = cmds.iter().rposition(|c| *c == "sshd -t").unwrap();
        let reload = cmds
            .iter()
            .position(|c| c.contains("systemctl reload ssh || systemctl reload sshd"))
            .unwrap();
        let effective = cmds.iter().position(|c| *c == "sshd -T").unwrap();
        assert!(pre < write && write < old && old < test && test < reload && reload < effective);
        assert_eq!(
            fake.log[write].1.as_deref(),
            Some(&b"PasswordAuthentication no\n"[..])
        );
    }

    #[tokio::test]
    async fn rejected_sshd_config_is_undone_and_not_reloaded() {
        let mut fake = Fake::server(UBUNTU, "", "0\n");
        // Valid before the change, rejected after it.
        fake.on("sshd -t", 255, "");
        fake.sshd_t_ok_first = true;
        let (r, _) = go(&mut fake, opts(false, false, true), true, 22, &keys()).await;
        assert!(r.unwrap_err().0.starts_with("Turning off SSH passwords: "));
        let cmds = fake.cmds();
        assert!(cmds.contains(&"rm -f /etc/ssh/sshd_config.d/01-keel.conf"));
        assert!(!cmds.iter().any(|c| c.contains("reload ssh")));
    }

    #[tokio::test]
    async fn broken_existing_sshd_config_is_left_alone() {
        let mut fake = Fake::server(UBUNTU, "", "0\n");
        fake.on("sshd -t", 255, "");
        let (r, evs) = go(&mut fake, opts(false, false, true), true, 22, &keys()).await;
        r.unwrap();
        let sshd: Vec<&str> = fake
            .cmds()
            .into_iter()
            .filter(|c| c.contains("ssh"))
            .collect();
        assert_eq!(sshd, ["sshd -t"], "nothing touched: {sshd:?}");
        assert!(evs.iter().any(|e| matches!(e, OnboardingEvent::Findings(f)
            if f[0].message == "Your current SSH configuration has errors, so Keel left it unchanged.")));
    }

    #[tokio::test]
    async fn overridden_password_setting_warns() {
        let mut fake = Fake::server(UBUNTU, "", "0\n");
        fake.on("sshd -T", 0, "port 22\npasswordauthentication yes\n");
        let (r, evs) = go(&mut fake, opts(false, false, true), true, 22, &keys()).await;
        r.unwrap();
        assert!(evs.iter().any(|e| matches!(e, OnboardingEvent::Findings(f)
            if f[0].severity == Severity::Warning
                && f[0].message.contains("Another SSH configuration file"))));
    }

    #[tokio::test]
    async fn confirmed_password_setting_does_not_warn() {
        let mut fake = Fake::server(UBUNTU, "", "0\n");
        let (r, evs) = go(&mut fake, opts(false, false, true), true, 22, &keys()).await;
        r.unwrap();
        assert!(
            !evs.iter()
                .any(|e| matches!(e, OnboardingEvent::Findings(_)))
        );
    }

    #[tokio::test]
    async fn bad_signature_names_the_step() {
        let mut k = keys();
        k.artifacts.x86_64.as_mut().unwrap().1[0] ^= 1;
        let mut fake = Fake::server(UBUNTU, "", "0\n");
        let (r, _) = go(&mut fake, opts(false, false, false), true, 22, &k).await;
        assert!(r.unwrap_err().0.starts_with("Checking the agent: "));
    }

    #[tokio::test]
    async fn failing_step_is_named_and_hides_stderr() {
        let mut fake = Fake::server(UBUNTU, "", "0\n");
        fake.on("systemctl restart keel-agent", 1, "");
        let (r, _) = go(&mut fake, opts(true, false, false), true, 22, &keys()).await;
        let msg = r.unwrap_err().0;
        assert!(msg.starts_with("Starting the agent: "), "{msg}");
        assert!(!msg.contains("boom"));
        // Stopped at the failure: no firewall changes after it.
        assert!(!fake.cmds().iter().any(|c| c.starts_with("ufw")));
    }

    #[tokio::test]
    async fn unreachable_agent_port_fails_with_advice() {
        let mut fake = Fake::server(UBUNTU, "", "0\n");
        fake.reachable = false;
        let (r, _) = go(&mut fake, opts(false, false, false), true, 22, &keys()).await;
        let msg = r.unwrap_err().0;
        assert_eq!(
            msg,
            "Starting the agent: The agent started but Keel can't reach port 7443. Allow it in your server's firewall and your hosting provider's firewall, then try again."
        );
    }

    #[tokio::test]
    async fn corrupted_upload_is_removed() {
        let mut fake = CorruptingFake(Fake::server(UBUNTU, "", "0\n"));
        let k = keys();
        let (tx, _rx) = mpsc::channel(64);
        let o = opts(false, false, false);
        let plan = Plan {
            host: "h",
            ssh_port: 22,
            opts: &o,
            key_auth: true,
            artifacts: &k.artifacts,
            pubkey: &k.pubkey,
        };
        let r = install(&mut fake, &plan, &tx).await;
        assert!(r.unwrap_err().0.contains("damaged"));
        let cmds = fake.0.cmds();
        assert!(cmds.contains(&"rm -f /usr/local/bin/keel-agent.new"));
        assert!(!cmds.iter().any(|c| c.starts_with("mv -f")));
    }

    /// Reports a wrong hash for every upload.
    struct CorruptingFake(Fake);

    impl Remote for CorruptingFake {
        async fn exec(&mut self, cmd: &str, stdin: Option<&[u8]>) -> anyhow::Result<ExecOutput> {
            if cmd.contains("sha256sum") {
                self.0.log.push((cmd.to_string(), None));
                return Ok((0, format!("{}  x\n", "0".repeat(64)), String::new()));
            }
            self.0.exec(cmd, stdin).await
        }
        async fn reachable(&mut self, port: u16, within: Duration) -> bool {
            self.0.reachable(port, within).await
        }
    }

    #[test]
    fn parse_init_requires_matching_fingerprint() {
        let code = |fp: &str| {
            PairingCode {
                host: "h".into(),
                port: 7443,
                fingerprint: fp.into(),
                token: "t".into(),
            }
            .encode()
        };
        let ok = format!("fingerprint=aa\npairing_code={}\n", code("aa"));
        assert_eq!(parse_init(&ok), Some(("aa".into(), "t".into())));
        let mismatch = format!("fingerprint=aa\npairing_code={}\n", code("bb"));
        assert_eq!(parse_init(&mismatch), None);
        assert_eq!(parse_init("fingerprint=aa\n"), None);
        assert_eq!(parse_init(""), None);
    }

    #[test]
    fn shell_quote_escapes_single_quotes() {
        assert_eq!(shell_quote("a'b"), r"'a'\''b'");
        assert_eq!(shell_quote("x; rm -rf /"), "'x; rm -rf /'");
    }
}
