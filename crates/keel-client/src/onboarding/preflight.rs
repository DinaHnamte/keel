//! Parse facts gathered from a server and decide whether Keel can be installed.
//! Everything here is pure: the SSH commands that produce the inputs live elsewhere.

use serde::{Deserialize, Serialize};

const MIN_FREE_BYTES: u64 = 1_073_741_824;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FirewallKind {
    Ufw,
    Firewalld,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostFacts {
    pub os_id: String,
    pub os_version: String,
    /// Human-readable OS name (PRETTY_NAME, or ID + VERSION_ID when absent).
    pub os_name: String,
    pub arch: String,
    pub has_systemd: bool,
    pub free_disk_bytes: u64,
    pub ports_in_use: Vec<u16>,
    pub ssh_port: u16,
    pub is_root: bool,
    pub has_sudo: bool,
    pub firewall: FirewallKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Support {
    Full,
    BestEffort(String),
    Unsupported(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Blocker,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallOptions {
    pub enable_firewall: bool,
    pub auto_security_updates: bool,
    pub disable_ssh_passwords: bool,
    pub keep_ssh_credentials: bool,
}

impl Default for InstallOptions {
    fn default() -> Self {
        Self {
            enable_firewall: true,
            auto_security_updates: true,
            disable_ssh_passwords: false,
            keep_ssh_credentials: false,
        }
    }
}

/// Look up `key` in os-release content, stripping surrounding quotes.
fn os_release_value(content: &str, key: &str) -> Option<String> {
    content.lines().find_map(|line| {
        let (k, v) = line.split_once('=')?;
        if k.trim() != key {
            return None;
        }
        let v = v.trim().trim_matches(|c| c == '"' || c == '\'');
        Some(v.to_string())
    })
}

/// Extract the port from an `ss` local-address column such as `0.0.0.0:80`,
/// `[::]:443`, `*:22` or `127.0.0.53%lo:53`.
fn port_of(addr: &str) -> Option<u16> {
    addr.rsplit_once(':')?.1.parse().ok()
}

#[allow(clippy::too_many_arguments)]
pub fn parse_facts(
    os_release: &str,
    uname_m: &str,
    systemctl_ok: bool,
    df_out: &str,
    ss_out: &str,
    ssh_port: u16,
    id_u: &str,
    sudo_ok: bool,
    fw: FirewallKind,
) -> HostFacts {
    let os_id = os_release_value(os_release, "ID").unwrap_or_default();
    let os_version = os_release_value(os_release, "VERSION_ID").unwrap_or_default();
    let os_name = match os_release_value(os_release, "PRETTY_NAME").filter(|n| !n.is_empty()) {
        // "CentOS Linux 7 (Core)" reads better as "CentOS Linux 7".
        Some(n) => match n.find(" (") {
            Some(i) => n[..i].to_string(),
            None => n,
        },
        None => format!("{os_id} {os_version}").trim().to_string(),
    };

    let arch = match uname_m.trim() {
        "arm64" => "aarch64".to_string(),
        other => other.to_string(),
    };

    let free_disk_bytes = df_out
        .lines()
        .filter_map(|l| l.trim().parse::<u64>().ok())
        .next()
        .unwrap_or(0);

    let mut ports_in_use: Vec<u16> = ss_out
        .lines()
        .filter_map(|l| l.split_whitespace().nth(3))
        .filter_map(port_of)
        .collect();
    ports_in_use.sort_unstable();
    ports_in_use.dedup();

    HostFacts {
        os_id,
        os_version,
        os_name,
        arch,
        has_systemd: systemctl_ok,
        free_disk_bytes,
        ports_in_use,
        ssh_port,
        is_root: id_u.trim() == "0",
        has_sudo: sudo_ok,
        firewall: fw,
    }
}

pub fn support(f: &HostFacts) -> Support {
    let v = f.os_version.as_str();
    match f.os_id.as_str() {
        "ubuntu" if v == "22.04" || v == "24.04" => Support::Full,
        "debian" if v == "12" || v == "13" => Support::Full,
        id @ ("almalinux" | "rocky" | "ol") if v.split('.').next() == Some("9") => {
            let family = match id {
                "almalinux" => "AlmaLinux",
                "rocky" => "Rocky Linux",
                _ => "Oracle Linux",
            };
            Support::BestEffort(format!(
                "{family} {v} is supported on a best-effort basis. Some features may need manual fixes."
            ))
        }
        _ => Support::Unsupported(format!(
            "{} isn't supported. Keel supports Ubuntu 22.04 and 24.04, and Debian 12 and 13.",
            f.os_name
        )),
    }
}

pub fn preflight(f: &HostFacts, agent_port: u16) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut add = |severity, message: String| out.push(Finding { severity, message });

    match support(f) {
        Support::Full => {}
        Support::BestEffort(m) => add(Severity::Warning, m),
        Support::Unsupported(m) => add(Severity::Blocker, m),
    }
    if f.arch != "x86_64" && f.arch != "aarch64" {
        let arch = if f.arch.is_empty() {
            "unknown"
        } else {
            f.arch.as_str()
        };
        add(
            Severity::Blocker,
            format!(
                "This server's processor ({arch}) isn't supported. Keel needs x86_64 or ARM64."
            ),
        );
    }
    if !f.has_systemd {
        add(
            Severity::Blocker,
            "This server doesn't use systemd, which Keel needs to run its agent.".into(),
        );
    }
    if f.free_disk_bytes < MIN_FREE_BYTES {
        add(
            Severity::Blocker,
            "This server has less than 1 GB of free disk space. Free some space and try again."
                .into(),
        );
    }
    if !f.is_root && !f.has_sudo {
        add(
            Severity::Blocker,
            "The SSH user needs to be root or have passwordless sudo.".into(),
        );
    }
    if f.ports_in_use.contains(&agent_port) {
        add(
            Severity::Blocker,
            format!("Port {agent_port} is already in use on this server. Keel's agent needs it."),
        );
    }
    for port in [80u16, 443] {
        if f.ports_in_use.contains(&port) {
            add(
                Severity::Warning,
                format!(
                    "Port {port} is in use by another program. Websites won't work until it's freed."
                ),
            );
        }
    }
    out
}

/// Ports the firewall must allow: SSH (as actually configured), web, and the agent.
pub fn firewall_rules(f: &HostFacts, agent_port: u16) -> Vec<u16> {
    let mut rules = Vec::new();
    for p in [f.ssh_port, 80, 443, agent_port] {
        if !rules.contains(&p) {
            rules.push(p);
        }
    }
    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    const UBUNTU_2404: &str = "PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\nID_LIKE=debian\n";
    const DEBIAN_13: &str =
        "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nVERSION_ID=\"13\"\nID=debian\n";
    const ROCKY_9: &str = "NAME=\"Rocky Linux\"\nVERSION_ID=\"9.4\"\nID=\"rocky\"\nPRETTY_NAME=\"Rocky Linux 9.4 (Blue Onyx)\"\n";
    const ALMA_9: &str = "ID=\"almalinux\"\nVERSION_ID=\"9.3\"\nPRETTY_NAME=\"AlmaLinux 9.3 (Shamrock Pampas Cat)\"\n";
    const CENTOS_7: &str = "NAME=\"CentOS Linux\"\nVERSION_ID=\"7\"\nID=\"centos\"\nPRETTY_NAME=\"CentOS Linux 7 (Core)\"\n";
    const DF: &str = "      Avail\n 21474836480\n";
    const SS: &str = "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 128 [::]:22 [::]:*\nLISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*\n";

    fn facts(os: &str, arch: &str, ss: &str) -> HostFacts {
        parse_facts(os, arch, true, DF, ss, 22, "0", false, FirewallKind::None)
    }

    fn msgs(fs: &[Finding], sev: Severity) -> Vec<&str> {
        fs.iter()
            .filter(|f| f.severity == sev)
            .map(|f| f.message.as_str())
            .collect()
    }

    #[test]
    fn ubuntu_2404_full() {
        let f = facts(UBUNTU_2404, "x86_64\n", SS);
        assert_eq!(
            (f.os_id.as_str(), f.os_version.as_str()),
            ("ubuntu", "24.04")
        );
        assert_eq!(f.free_disk_bytes, 21_474_836_480);
        assert!(f.is_root && f.has_systemd);
        assert_eq!(support(&f), Support::Full);
        assert!(preflight(&f, 7443).is_empty());
    }

    #[test]
    fn ubuntu_2204_full() {
        let f = facts("ID=ubuntu\nVERSION_ID=\"22.04\"\n", "x86_64", "");
        assert_eq!(support(&f), Support::Full);
    }

    #[test]
    fn debian_13_full() {
        let f = facts(DEBIAN_13, "x86_64", "");
        assert_eq!(support(&f), Support::Full);
        let f = facts("ID=debian\nVERSION_ID=\"12\"\n", "x86_64", "");
        assert_eq!(support(&f), Support::Full);
    }

    #[test]
    fn rocky_9_best_effort() {
        let f = facts(ROCKY_9, "x86_64", "");
        assert!(matches!(support(&f), Support::BestEffort(_)));
        let fs = preflight(&f, 7443);
        assert!(msgs(&fs, Severity::Blocker).is_empty());
        assert_eq!(msgs(&fs, Severity::Warning).len(), 1);
    }

    const ORACLE_9: &str = "NAME=\"Oracle Linux Server\"\nVERSION=\"9.8\"\nID=\"ol\"\nID_LIKE=\"fedora\"\nVERSION_ID=\"9.8\"\nPRETTY_NAME=\"Oracle Linux Server 9.8\"\n";

    #[test]
    fn oracle_linux_9_best_effort_message() {
        let f = facts(ORACLE_9, "aarch64", "");
        let fs = preflight(&f, 7443);
        assert!(msgs(&fs, Severity::Blocker).is_empty());
        assert_eq!(
            msgs(&fs, Severity::Warning),
            [
                "Oracle Linux 9.8 is supported on a best-effort basis. Some features may need manual fixes."
            ]
        );
    }

    #[test]
    fn rhel_family_needs_major_version_9_exactly() {
        let f = facts("ID=\"rocky\"\nVERSION_ID=\"90\"\n", "x86_64", "");
        assert!(matches!(support(&f), Support::Unsupported(_)));
        let f = facts("ID=\"ol\"\nVERSION_ID=\"8.10\"\n", "x86_64", "");
        assert!(matches!(support(&f), Support::Unsupported(_)));
    }

    #[test]
    fn alma_9_best_effort_message() {
        let f = facts(ALMA_9, "x86_64", "");
        let fs = preflight(&f, 7443);
        assert_eq!(
            msgs(&fs, Severity::Warning),
            [
                "AlmaLinux 9.3 is supported on a best-effort basis. Some features may need manual fixes."
            ]
        );
    }

    #[test]
    fn centos_7_unsupported_message_names_os() {
        let f = facts(CENTOS_7, "x86_64", "");
        let Support::Unsupported(m) = support(&f) else {
            panic!("expected unsupported")
        };
        assert_eq!(
            m,
            "CentOS Linux 7 isn't supported. Keel supports Ubuntu 22.04 and 24.04, and Debian 12 and 13."
        );
        let fs = preflight(&f, 7443);
        assert_eq!(msgs(&fs, Severity::Blocker), [m.as_str()]);
    }

    #[test]
    fn unknown_os_falls_back_to_id_and_version() {
        let f = facts("ID=arch\nVERSION_ID=\"2024\"\n", "x86_64", "");
        let Support::Unsupported(m) = support(&f) else {
            panic!()
        };
        assert!(m.starts_with("arch 2024 isn't supported."), "{m}");
    }

    #[test]
    fn arm64_reported_as_aarch64_supported() {
        let f = facts(UBUNTU_2404, "arm64\n", "");
        assert_eq!(f.arch, "aarch64");
        assert!(preflight(&f, 7443).is_empty());
    }

    #[test]
    fn unsupported_arch_blocks() {
        let f = facts(UBUNTU_2404, "riscv64", "");
        assert_eq!(
            msgs(&preflight(&f, 7443), Severity::Blocker),
            ["This server's processor (riscv64) isn't supported. Keel needs x86_64 or ARM64."]
        );
    }

    #[test]
    fn no_systemd_blocks() {
        let f = parse_facts(
            UBUNTU_2404,
            "x86_64",
            false,
            DF,
            "",
            22,
            "0",
            false,
            FirewallKind::None,
        );
        assert_eq!(
            msgs(&preflight(&f, 7443), Severity::Blocker),
            ["This server doesn't use systemd, which Keel needs to run its agent."]
        );
    }

    #[test]
    fn low_disk_and_unparseable_df_block() {
        let low = parse_facts(
            UBUNTU_2404,
            "x86_64",
            true,
            "Avail\n1073741823\n",
            "",
            22,
            "0",
            false,
            FirewallKind::None,
        );
        let junk = parse_facts(
            UBUNTU_2404,
            "x86_64",
            true,
            "garbage",
            "",
            22,
            "0",
            false,
            FirewallKind::None,
        );
        assert_eq!(junk.free_disk_bytes, 0);
        for f in [low, junk] {
            assert_eq!(
                msgs(&preflight(&f, 7443), Severity::Blocker),
                [
                    "This server has less than 1 GB of free disk space. Free some space and try again."
                ]
            );
        }
        let exact = parse_facts(
            UBUNTU_2404,
            "x86_64",
            true,
            "Avail\n1073741824\n",
            "",
            22,
            "0",
            false,
            FirewallKind::None,
        );
        assert!(preflight(&exact, 7443).is_empty());
    }

    #[test]
    fn not_root_needs_sudo() {
        let f = parse_facts(
            UBUNTU_2404,
            "x86_64",
            true,
            DF,
            "",
            22,
            "1000",
            false,
            FirewallKind::None,
        );
        assert!(!f.is_root);
        assert_eq!(
            msgs(&preflight(&f, 7443), Severity::Blocker),
            ["The SSH user needs to be root or have passwordless sudo."]
        );
        let ok = parse_facts(
            UBUNTU_2404,
            "x86_64",
            true,
            DF,
            "",
            22,
            "1000",
            true,
            FirewallKind::None,
        );
        assert!(preflight(&ok, 7443).is_empty());
    }

    #[test]
    fn parses_all_ss_address_shapes() {
        let ss = "LISTEN 0 511 0.0.0.0:80 0.0.0.0:*\nLISTEN 0 511 [::]:443 [::]:*\nLISTEN 0 128 *:22 *:*\nLISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*\nLISTEN 0 511 0.0.0.0:80 0.0.0.0:*\nLISTEN 0 1 [::1]:631 [::]:*\nshort line\n";
        let f = facts(UBUNTU_2404, "x86_64", ss);
        assert_eq!(f.ports_in_use, [22, 53, 80, 443, 631]);
    }

    #[test]
    fn port_80_busy_is_warning_not_blocker() {
        let f = facts(UBUNTU_2404, "x86_64", "LISTEN 0 511 0.0.0.0:80 0.0.0.0:*\n");
        let fs = preflight(&f, 7443);
        assert!(msgs(&fs, Severity::Blocker).is_empty());
        assert_eq!(
            msgs(&fs, Severity::Warning),
            ["Port 80 is in use by another program. Websites won't work until it's freed."]
        );
    }

    #[test]
    fn port_443_busy_is_warning() {
        let f = facts(UBUNTU_2404, "x86_64", "LISTEN 0 511 [::]:443 [::]:*\n");
        assert_eq!(
            msgs(&preflight(&f, 7443), Severity::Warning),
            ["Port 443 is in use by another program. Websites won't work until it's freed."]
        );
    }

    #[test]
    fn agent_port_busy_is_blocker() {
        let f = facts(
            UBUNTU_2404,
            "x86_64",
            "LISTEN 0 128 0.0.0.0:7443 0.0.0.0:*\n",
        );
        let fs = preflight(&f, 7443);
        assert_eq!(
            msgs(&fs, Severity::Blocker),
            ["Port 7443 is already in use on this server. Keel's agent needs it."]
        );
        assert!(msgs(&fs, Severity::Warning).is_empty());
    }

    #[test]
    fn firewall_keeps_nonstandard_ssh_port() {
        let mut f = facts(UBUNTU_2404, "x86_64", "");
        f.ssh_port = 2222;
        let rules = firewall_rules(&f, 7443);
        assert_eq!(rules, [2222, 80, 443, 7443]);
        assert!(!rules.contains(&22));
    }

    #[test]
    fn firewall_rules_deduplicate() {
        let mut f = facts(UBUNTU_2404, "x86_64", "");
        f.ssh_port = 80;
        assert_eq!(firewall_rules(&f, 443), [80, 443]);
    }

    #[test]
    fn install_option_defaults_and_serde() {
        let o = InstallOptions::default();
        assert!(o.enable_firewall && o.auto_security_updates);
        assert!(!o.disable_ssh_passwords && !o.keep_ssh_credentials);
        let back: InstallOptions =
            serde_json::from_str(&serde_json::to_string(&o).unwrap()).unwrap();
        assert_eq!(back, o);
    }

    #[test]
    fn empty_inputs_do_not_panic() {
        let f = parse_facts("", "", false, "", "", 22, "", false, FirewallKind::None);
        assert_eq!(f.free_disk_bytes, 0);
        assert!(!f.is_root);
        assert!(matches!(support(&f), Support::Unsupported(_)));
        assert!(!preflight(&f, 7443).is_empty());
    }
}
