//! End-to-end onboarding against a real server (a systemd container with
//! sshd, see CI). Ignored by default; each test skips unless these are set:
//! KEEL_TEST_SSH_HOST, KEEL_TEST_SSH_PORT, KEEL_TEST_SSH_USER,
//! KEEL_TEST_SSH_KEY_FILE, KEEL_TEST_AGENT_BIN, KEEL_TEST_AGENT_SIG.
//! The agent binary must be signed with the key this build embeds.

use keel_client::onboarding::{
    AgentArtifacts, InstallOptions, OnboardingEvent, Remote, SshAuth, SshSession, SshTarget,
    run_onboarding,
};
use keel_client::{Connection, DeviceIdentity, Keychain, MemoryKeychain};
use keel_proto::{Request, Response, Role};
use tokio::sync::mpsc;

struct Env {
    target: SshTarget,
    artifacts: AgentArtifacts,
}

fn env() -> Option<Env> {
    let get = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let vars = [
        "KEEL_TEST_SSH_HOST",
        "KEEL_TEST_SSH_PORT",
        "KEEL_TEST_SSH_USER",
        "KEEL_TEST_SSH_KEY_FILE",
        "KEEL_TEST_AGENT_BIN",
        "KEEL_TEST_AGENT_SIG",
    ];
    if let Some(missing) = vars.iter().find(|k| get(k).is_none()) {
        eprintln!("skipping: {missing} is not set");
        return None;
    }
    let pem = std::fs::read_to_string(get("KEEL_TEST_SSH_KEY_FILE")?).unwrap();
    let bin = std::fs::read(get("KEEL_TEST_AGENT_BIN")?).unwrap();
    let sig: [u8; 64] = std::fs::read(get("KEEL_TEST_AGENT_SIG")?)
        .unwrap()
        .try_into()
        .expect("signature is 64 bytes");
    let artifacts = AgentArtifacts {
        x86_64: Some((bin.clone(), sig)),
        aarch64: Some((bin, sig)),
    };
    Some(Env {
        target: SshTarget {
            host: get("KEEL_TEST_SSH_HOST")?,
            port: get("KEEL_TEST_SSH_PORT")?.parse().unwrap(),
            user: get("KEEL_TEST_SSH_USER")?,
            auth: SshAuth::PrivateKey {
                pem: pem.into(),
                passphrase: None,
            },
        },
        artifacts,
    })
}

fn opts() -> InstallOptions {
    InstallOptions {
        enable_firewall: true,
        auto_security_updates: false,
        disable_ssh_passwords: false,
        keep_ssh_credentials: false,
    }
}

async fn onboard(
    e: &Env,
    opts: InstallOptions,
    id: &DeviceIdentity,
    kc: &dyn Keychain,
) -> (
    anyhow::Result<keel_client::ServerRecord>,
    Vec<OnboardingEvent>,
) {
    let (tx, mut rx) = mpsc::channel(256);
    let r = run_onboarding(
        e.target.clone(),
        "test server".into(),
        "test device".into(),
        opts,
        &e.artifacts,
        id,
        kc,
        tx,
    )
    .await;
    let mut evs = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        evs.push(ev);
    }
    (r, evs)
}

async fn ssh(e: &Env) -> SshSession {
    let mut s = SshSession::connect(&e.target.host, e.target.port)
        .await
        .unwrap();
    s.authenticate(&e.target.user, &e.target.auth)
        .await
        .unwrap();
    s
}

async fn sh(s: &mut SshSession, cmd: &str) -> (i32, String) {
    let (code, out, _) = s.exec(cmd, None).await.unwrap();
    (code, out)
}

/// Run `script` as root: through `sudo -n` unless the SSH user is root.
async fn root(s: &mut SshSession, script: &str) -> (i32, String) {
    let quoted = format!("'{}'", script.replace('\'', r"'\''"));
    let is_root = sh(s, "id -u").await.1.trim() == "0";
    let cmd = if is_root {
        format!("sh -c {quoted}")
    } else {
        format!("sudo -n sh -c {quoted}")
    };
    sh(s, &cmd).await
}

#[tokio::test]
#[ignore]
async fn onboard_fresh_server() {
    let Some(e) = env() else { return };
    let kc = MemoryKeychain::new();
    let id = DeviceIdentity::load_or_create(&kc).unwrap();
    let mut o = opts();
    o.keep_ssh_credentials = true;
    let (r, evs) = onboard(&e, o, &id, &kc).await;
    let rec = r.unwrap();
    assert_eq!(rec.name, "test server");
    assert!(rec.ssh_saved);
    assert!(kc.get(&format!("ssh:{}", rec.id)).unwrap().is_some());
    assert!(matches!(evs.first(), Some(OnboardingEvent::Connecting)));
    assert!(
        evs.iter()
            .any(|e| matches!(e, OnboardingEvent::HostKey(k) if k.starts_with("SHA256:")))
    );
    assert!(matches!(evs.last(), Some(OnboardingEvent::Done(_))));

    let (mut conn, _) = Connection::open(&rec, &id).await.unwrap();
    match conn.request(Request::WhoAmI).await.unwrap() {
        Response::Me(u) => assert_eq!(u.role, Role::Owner),
        other => panic!("expected Me, got {other:?}"),
    }
}

#[tokio::test]
#[ignore]
async fn onboard_twice_is_idempotent() {
    let Some(e) = env() else { return };
    let kc = MemoryKeychain::new();
    let id = DeviceIdentity::load_or_create(&kc).unwrap();
    let first = onboard(&e, opts(), &id, &kc).await.0.unwrap();
    let second = onboard(&e, opts(), &id, &kc).await.0.unwrap();
    assert_eq!(first.fingerprint, second.fingerprint);
    assert_eq!(first.id, second.id);

    let (mut conn, _) = Connection::open(&second, &id).await.unwrap();
    let Response::Users(users) = conn.request(Request::ListUsers).await.unwrap() else {
        panic!("expected users")
    };
    let mine: Vec<_> = users
        .iter()
        .filter(|u| u.key_fingerprint == id.fingerprint)
        .collect();
    assert_eq!(mine.len(), 1, "one Owner per device: {users:?}");
    assert_eq!(mine[0].role, Role::Owner);

    // A second device pairs with the token the second run issued.
    let kc2 = MemoryKeychain::new();
    let id2 = DeviceIdentity::load_or_create(&kc2).unwrap();
    let rec2 = onboard(&e, opts(), &id2, &kc2).await.0.unwrap();
    assert_eq!(rec2.fingerprint, first.fingerprint);
}

#[tokio::test]
#[ignore]
async fn onboard_blocked_makes_no_changes() {
    let Some(e) = env() else { return };
    let mut s = ssh(&e).await;
    // A clean server, with something else holding the agent's port.
    root(
        &mut s,
        "systemctl disable --now keel-agent 2>/dev/null; \
         rm -f /usr/local/bin/keel-agent /etc/systemd/system/keel-agent.service; \
         systemctl daemon-reload; userdel keel 2>/dev/null; true",
    )
    .await;
    // OpenBSD nc takes `-l 7443`; traditional nc needs `-l -p 7443`.
    root(
        &mut s,
        "(nohup nc -l -p 7443 >/dev/null 2>&1 &); sleep 0.5; \
         ss -Htln | grep -q ':7443 ' || (nohup nc -l 7443 >/dev/null 2>&1 &)",
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(
        sh(&mut s, "ss -Htln | grep -q ':7443 '").await.0,
        0,
        "port 7443 should be held"
    );

    let kc = MemoryKeychain::new();
    let id = DeviceIdentity::load_or_create(&kc).unwrap();
    let (r, evs) = onboard(&e, opts(), &id, &kc).await;
    let msg = r.unwrap_err().to_string();
    assert!(msg.contains("Port 7443 is already in use"), "{msg}");
    assert!(matches!(evs.last(), Some(OnboardingEvent::Failed(_))));
    assert!(
        !evs.iter()
            .any(|e| matches!(e, OnboardingEvent::Installing(_)))
    );

    let bin = sh(&mut s, "test -e /usr/local/bin/keel-agent").await.0;
    let unit = sh(&mut s, "test -e /etc/systemd/system/keel-agent.service")
        .await
        .0;
    let user = sh(&mut s, "id keel").await.0;
    root(&mut s, "pkill -f 'nc -l' ; true").await;
    assert_ne!(bin, 0, "/usr/local/bin/keel-agent must not exist");
    assert_ne!(unit, 0, "the unit file must not exist");
    assert_ne!(user, 0, "the keel user must not exist");
}

#[tokio::test]
#[ignore]
async fn onboard_ssh_2222_firewall_keeps_access() {
    let Some(e) = env() else { return };
    if e.target.port == 22 {
        eprintln!("skipping: needs KEEL_TEST_SSH_PORT set to a non-standard port such as 2222");
        return;
    }
    let kc = MemoryKeychain::new();
    let id = DeviceIdentity::load_or_create(&kc).unwrap();
    onboard(&e, opts(), &id, &kc).await.0.unwrap();
    // The firewall is on and SSH still works on the same port.
    let mut s = ssh(&e).await;
    let (code, out) = sh(&mut s, "ufw status || firewall-cmd --list-ports").await;
    assert_eq!(code, 0);
    assert!(out.contains(&e.target.port.to_string()), "{out}");
}
