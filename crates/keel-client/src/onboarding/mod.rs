//! Onboarding: check a server over SSH, install the agent and pair with it.

pub mod artifact;
pub mod install;
pub mod preflight;
pub mod ssh;

use anyhow::anyhow;
use serde::Serialize;
use tokio::sync::mpsc::Sender;

use crate::connection::pair_or_confirm;
use crate::identity::{DeviceIdentity, Keychain};
use crate::servers::ServerRecord;

pub use artifact::{RELEASE_PUBKEY, verify_agent_artifact};
pub use install::{AGENT_PORT, AgentArtifacts, ExecOutput, Remote};
pub use preflight::{
    Finding, FirewallKind, HostFacts, InstallOptions, Severity, Support, firewall_rules,
    parse_facts, preflight, support,
};
pub use ssh::{SshAuth, SshSession, SshTarget, generate_ssh_keypair};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", content = "data")]
pub enum OnboardingEvent {
    Connecting,
    /// The SSH server's host key, `SHA256:<base64>`. Trusted on first use.
    HostKey(String),
    Checking,
    Findings(Vec<Finding>),
    Installing(&'static str),
    Pairing,
    Done(ServerRecord),
    Failed(String),
}

/// What is saved in the keychain under `ssh:<server_id>` when the person
/// chose to keep SSH credentials.
#[derive(Serialize)]
struct SavedSsh<'a> {
    host: &'a str,
    port: u16,
    user: &'a str,
    auth: &'a SshAuth,
    host_key: &'a str,
}

/// Connect over SSH, check the server, install and start the agent, and pair
/// this device as its owner. Every step is safe to repeat. Progress and the
/// outcome are sent on `events`; on failure the last event is `Failed`.
#[allow(clippy::too_many_arguments)]
pub async fn run_onboarding(
    target: SshTarget,
    server_name: String,
    device_name: String,
    opts: InstallOptions,
    artifacts: &AgentArtifacts,
    id: &DeviceIdentity,
    kc: &dyn Keychain,
    events: Sender<OnboardingEvent>,
) -> anyhow::Result<ServerRecord> {
    let opts = effective_options(opts);
    let result = onboard(
        &target,
        &server_name,
        &device_name,
        &opts,
        artifacts,
        id,
        kc,
        &events,
    )
    .await;
    match result {
        Ok(rec) => {
            let _ = events.send(OnboardingEvent::Done(rec.clone())).await;
            Ok(rec)
        }
        Err(msg) => {
            let _ = events.send(OnboardingEvent::Failed(msg.clone())).await;
            Err(anyhow!(msg))
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn onboard(
    target: &SshTarget,
    server_name: &str,
    device_name: &str,
    opts: &InstallOptions,
    artifacts: &AgentArtifacts,
    id: &DeviceIdentity,
    kc: &dyn Keychain,
    events: &Sender<OnboardingEvent>,
) -> Result<ServerRecord, String> {
    const CONNECT: &str = "Connecting";
    let _ = events.send(OnboardingEvent::Connecting).await;
    let mut session = SshSession::connect(&target.host, target.port)
        .await
        .map_err(|e| format!("{CONNECT}: {e}"))?;
    let _ = events
        .send(OnboardingEvent::HostKey(session.host_key.clone()))
        .await;
    session
        .authenticate(&target.user, &target.auth)
        .await
        .map_err(|e| format!("{CONNECT}: {e}"))?;

    let plan = install::Plan {
        host: &target.host,
        ssh_port: target.port,
        opts,
        key_auth: matches!(target.auth, SshAuth::PrivateKey { .. }),
        artifacts,
        pubkey: &RELEASE_PUBKEY,
    };
    let installed = install::install(&mut session, &plan, events).await;
    let host_key = session.host_key.clone();
    session.close().await;
    let installed = installed.map_err(|e| e.0)?;

    const PAIR: &str = "Pairing";
    let _ = events.send(OnboardingEvent::Pairing).await;
    let mut rec = pair_or_confirm(
        &target.host,
        AGENT_PORT,
        &installed.fingerprint,
        &installed.token,
        device_name,
        id,
    )
    .await
    .map_err(|e| format!("{PAIR}: {e}"))?;
    rec.name = server_name.to_string();

    rec.ssh_saved = store_ssh_choice(kc, &rec.id, opts.keep_ssh_credentials, target, &host_key)
        .map_err(|e| format!("{PAIR}: {e}"))?;
    Ok(rec)
}

/// Turning SSH passwords off makes the key the only way in, so the key is
/// always kept (an app-generated key exists nowhere else).
fn effective_options(opts: InstallOptions) -> InstallOptions {
    InstallOptions {
        keep_ssh_credentials: opts.keep_ssh_credentials || opts.disable_ssh_passwords,
        ..opts
    }
}

/// Save the SSH sign-in when the person chose to keep it; otherwise remove
/// any sign-in saved by an earlier onboarding of the same server. Returns
/// whether a sign-in is now saved.
fn store_ssh_choice(
    kc: &dyn Keychain,
    server_id: &str,
    keep: bool,
    target: &SshTarget,
    host_key: &str,
) -> Result<bool, String> {
    if keep {
        save_ssh_credentials(kc, server_id, target, host_key)?;
        return Ok(true);
    }
    kc.delete(&format!("ssh:{server_id}")).map_err(|e| {
        tracing::debug!(error = %e, "keychain delete failed");
        "The server is ready, but an SSH sign-in saved earlier couldn't be removed from this device's keychain. Unlock the keychain and remove the server, then add it again.".to_string()
    })?;
    Ok(false)
}

fn save_ssh_credentials(
    kc: &dyn Keychain,
    server_id: &str,
    target: &SshTarget,
    host_key: &str,
) -> Result<(), String> {
    let saved = SavedSsh {
        host: &target.host,
        port: target.port,
        user: &target.user,
        auth: &target.auth,
        host_key,
    };
    let json = zeroize::Zeroizing::new(
        serde_json::to_vec(&saved).map_err(|_| "Couldn't save the SSH sign-in.".to_string())?,
    );
    kc.set(&format!("ssh:{server_id}"), &json).map_err(|e| {
        tracing::debug!(error = %e, "keychain write failed");
        "The server is ready, but the SSH sign-in couldn't be saved to this device's keychain. Unlock the keychain and add the server again to save it.".to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::MemoryKeychain;
    use keel_agent::config::AgentConfig;
    use keel_agent::init::init;
    use keel_agent::server::{serve, system_clock};
    use keel_agent::store::Store;
    use crate::connection::pair;
    use keel_proto::Role;

    fn sha256(b: &[u8]) -> [u8; 32] {
        ring::digest::digest(&ring::digest::SHA256, b)
            .as_ref()
            .try_into()
            .unwrap()
    }

    fn opts(disable: bool, keep: bool) -> InstallOptions {
        InstallOptions {
            enable_firewall: false,
            auto_security_updates: false,
            disable_ssh_passwords: disable,
            keep_ssh_credentials: keep,
        }
    }

    #[test]
    fn disabling_passwords_forces_keeping_credentials() {
        assert!(effective_options(opts(true, false)).keep_ssh_credentials);
        assert!(effective_options(opts(true, true)).keep_ssh_credentials);
        assert!(!effective_options(opts(false, false)).keep_ssh_credentials);
        assert!(effective_options(opts(false, true)).keep_ssh_credentials);
        assert!(effective_options(opts(true, false)).disable_ssh_passwords);
    }

    #[test]
    fn reonboarding_without_keeping_removes_saved_credentials() {
        let kc = MemoryKeychain::new();
        let target = SshTarget {
            host: "203.0.113.5".into(),
            port: 22,
            user: "root".into(),
            auth: SshAuth::Password(zeroize::Zeroizing::new("pw".into())),
        };
        assert!(store_ssh_choice(&kc, "srv1", true, &target, "SHA256:abc").unwrap());
        assert!(kc.get("ssh:srv1").unwrap().is_some());
        // Added again with "keep SSH credentials" off.
        assert!(!store_ssh_choice(&kc, "srv1", false, &target, "SHA256:abc").unwrap());
        assert!(kc.get("ssh:srv1").unwrap().is_none());
        // Nothing saved before: still fine.
        assert!(!store_ssh_choice(&kc, "srv2", false, &target, "SHA256:abc").unwrap());
    }

    #[test]
    fn saved_credentials_hold_key_and_host_key() {
        let kc = MemoryKeychain::new();
        let (pem, _) = generate_ssh_keypair();
        let target = SshTarget {
            host: "203.0.113.5".into(),
            port: 2222,
            user: "root".into(),
            auth: SshAuth::PrivateKey {
                pem: zeroize::Zeroizing::new(pem.clone()),
                passphrase: None,
            },
        };
        save_ssh_credentials(&kc, "srv1", &target, "SHA256:abc").unwrap();
        let v: serde_json::Value =
            serde_json::from_slice(&kc.get("ssh:srv1").unwrap().unwrap()).unwrap();
        assert_eq!(v["host_key"], "SHA256:abc");
        assert_eq!(v["port"], 2222);
        assert_eq!(v["auth"]["PrivateKey"]["pem"], pem.as_str());
    }

    struct Agent {
        port: u16,
        fingerprint: String,
        token: String,
        dir: tempfile::TempDir,
        _stop: tokio::sync::oneshot::Sender<()>,
    }

    async fn agent() -> Agent {
        let dir = tempfile::tempdir().unwrap();
        let cfg = AgentConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            data_dir: dir.path().join("data"),
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let out = init(&cfg, "127.0.0.1", now).unwrap();
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(serve(l, cfg, system_clock(), async {
            let _ = rx.await;
        }));
        Agent {
            port,
            fingerprint: out.fingerprint,
            token: out.pairing_code.token,
            dir,
            _stop: tx,
        }
    }

    fn identity() -> DeviceIdentity {
        DeviceIdentity::load_or_create(&MemoryKeychain::new()).unwrap()
    }

    #[tokio::test]
    async fn rerun_confirms_owner_without_new_token() {
        let a = agent().await;
        let id = identity();
        let first = pair_or_confirm("127.0.0.1", a.port, &a.fingerprint, &a.token, "me", &id)
            .await
            .unwrap();
        // Same device again; the token is spent, so only WhoAmI can succeed.
        let again = pair_or_confirm("127.0.0.1", a.port, &a.fingerprint, &a.token, "me", &id)
            .await
            .unwrap();
        assert_eq!(first.id, again.id);
    }

    #[tokio::test]
    async fn rerun_as_non_owner_fails_plainly() {
        let a = agent().await;
        let store = Store::open(&a.dir.path().join("data").join("keel.db")).unwrap();
        store
            .create_pairing_token(&sha256(b"viewer-token"), Role::Viewer, i64::MAX / 2)
            .unwrap();
        let id = identity();
        pair(
            "127.0.0.1",
            a.port,
            &a.fingerprint,
            "viewer-token",
            "me",
            &id,
        )
        .await
        .unwrap();
        let err = pair_or_confirm("127.0.0.1", a.port, &a.fingerprint, &a.token, "me", &id)
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "This device is paired but isn't an owner of this server."
        );
    }
}
