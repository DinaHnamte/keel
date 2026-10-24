use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use keel_agent::config::AgentConfig;
use keel_agent::init::init;
use keel_agent::store::{RedeemError, Store};
use keel_proto::Role;
use sha2::{Digest, Sha256};

const NOW: i64 = 1_000_000;

fn cfg(dir: &std::path::Path) -> AgentConfig {
    AgentConfig {
        listen: "127.0.0.1:7443".parse().unwrap(),
        data_dir: dir.join("data"),
    }
}

fn hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

#[test]
fn init_creates_data_dir_cert_db_and_prints_code() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = cfg(tmp.path());
    let out = init(&cfg, "vps.example.com", NOW).unwrap();

    let mode = std::fs::metadata(&cfg.data_dir)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700);
    assert!(cfg.data_dir.join("keel.db").is_file());
    assert!(cfg.data_dir.join("tls/agent.crt").is_file());

    let code = &out.pairing_code;
    assert_eq!(code.host, "vps.example.com");
    assert_eq!(code.port, 7443);
    assert_eq!(code.fingerprint, out.fingerprint);
    assert_eq!(out.fingerprint.len(), 64);
    assert_eq!(URL_SAFE_NO_PAD.decode(&code.token).unwrap().len(), 32);

    // the stored token is the hash of the encoded string, and is redeemable
    let store = Store::open(&cfg.data_dir.join("keel.db")).unwrap();
    let u = store
        .redeem_pairing_token(&hash(&code.token), "fp", "Owner", NOW + 1)
        .unwrap();
    assert_eq!(u.role, Role::Owner);
}

#[test]
fn token_expires_after_24_hours() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = cfg(tmp.path());
    let out = init(&cfg, "h", NOW).unwrap();
    let store = Store::open(&cfg.data_dir.join("keel.db")).unwrap();
    let e = store
        .redeem_pairing_token(&hash(&out.pairing_code.token), "fp", "O", NOW + 86_400)
        .unwrap_err();
    assert!(matches!(e, RedeemError::Expired));
}

#[test]
fn init_twice_keeps_same_fingerprint() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = cfg(tmp.path());
    let a = init(&cfg, "h", NOW).unwrap();
    let b = init(&cfg, "h", NOW + 5).unwrap();
    assert_eq!(a.fingerprint, b.fingerprint);
    assert_ne!(a.pairing_code.token, b.pairing_code.token);
}

#[test]
fn init_twice_old_token_still_single_use() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = cfg(tmp.path());
    let a = init(&cfg, "h", NOW).unwrap();
    let store = Store::open(&cfg.data_dir.join("keel.db")).unwrap();
    store
        .redeem_pairing_token(&hash(&a.pairing_code.token), "fp1", "A", NOW + 1)
        .unwrap();
    let b = init(&cfg, "h", NOW + 2).unwrap();
    let e = store
        .redeem_pairing_token(&hash(&a.pairing_code.token), "fp2", "B", NOW + 3)
        .unwrap_err();
    assert!(matches!(e, RedeemError::Used));
    store
        .redeem_pairing_token(&hash(&b.pairing_code.token), "fp2", "B", NOW + 3)
        .unwrap();
}

#[test]
fn init_after_owner_exists_issues_owner_token() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = cfg(tmp.path());
    let a = init(&cfg, "h", NOW).unwrap();
    let store = Store::open(&cfg.data_dir.join("keel.db")).unwrap();
    store
        .redeem_pairing_token(&hash(&a.pairing_code.token), "fp1", "A", NOW + 1)
        .unwrap();
    let b = init(&cfg, "h", NOW + 2).unwrap();
    let u = store
        .redeem_pairing_token(&hash(&b.pairing_code.token), "fp-new", "A again", NOW + 3)
        .unwrap();
    assert_eq!(u.role, Role::Owner);
    assert_eq!(store.list_users().unwrap().len(), 2);
}

#[test]
fn binary_prints_exactly_two_lines() {
    let tmp = tempfile::tempdir().unwrap();
    let cfgfile = tmp.path().join("agent.toml");
    std::fs::write(&cfgfile, "listen = \"127.0.0.1:9555\"\n").unwrap();
    let data = tmp.path().join("d");
    let out = Command::new(env!("CARGO_BIN_EXE_keel-agent"))
        .args(["init", "--host", "vps.example.com", "--config"])
        .arg(&cfgfile)
        .arg("--data-dir")
        .arg(&data)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "{stdout:?}");
    assert!(stdout.ends_with('\n'));
    let fp = lines[0].strip_prefix("fingerprint=").unwrap();
    let code =
        keel_proto::PairingCode::parse(lines[1].strip_prefix("pairing_code=").unwrap()).unwrap();
    assert_eq!(code.fingerprint, fp);
    assert_eq!(code.port, 9555);
    assert_eq!(code.host, "vps.example.com");
    assert!(data.join("keel.db").is_file());
}

#[test]
fn binary_error_goes_to_stderr_exit_1() {
    let tmp = tempfile::tempdir().unwrap();
    let f = tmp.path().join("file");
    std::fs::write(&f, "x").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_keel-agent"))
        .args([
            "init",
            "--host",
            "h",
            "--config",
            "/nonexistent/a.toml",
            "--data-dir",
        ])
        .arg(f.join("sub"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert!(!out.stderr.is_empty());
}
