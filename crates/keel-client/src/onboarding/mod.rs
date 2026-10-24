//! Onboarding: check a server over SSH, install the agent and pair with it.

pub mod artifact;
pub mod install;
pub mod preflight;
pub mod ssh;

use anyhow::anyhow;
use keel_proto::Request;
use serde::Serialize;
use tokio::sync::mpsc::Sender;

use crate::connection::{ConnectError, Connection, pair};
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
        &installed.fingerprint,
        &installed.token,
        device_name,
        id,
    )
    .await
    .map_err(|e| format!("{PAIR}: {e}"))?;
    rec.name = server_name.to_string();

    if opts.keep_ssh_credentials {
        let saved = SavedSsh {
            host: &target.host,
            port: target.port,
            user: &target.user,
            auth: &target.auth,
            host_key: &host_key,
        };
        let json = zeroize::Zeroizing::new(
            serde_json::to_vec(&saved)
                .map_err(|_| format!("{PAIR}: Couldn't save the SSH sign-in."))?,
        );
        kc.set(&format!("ssh:{}", rec.id), &json).map_err(|e| {
            tracing::debug!(error = %e, "keychain write failed");
            format!(
                "{PAIR}: The server is ready, but the SSH sign-in couldn't be saved to this device's keychain. Unlock the keychain and add the server again to save it."
            )
        })?;
        rec.ssh_saved = true;
    }
    Ok(rec)
}

/// Pair with the fresh token. A device that is already paired (onboarding run
/// again) is confirmed instead by asking the agent who it is.
async fn pair_or_confirm(
    host: &str,
    fingerprint: &str,
    token: &str,
    device_name: &str,
    id: &DeviceIdentity,
) -> Result<ServerRecord, ConnectError> {
    let probe = ServerRecord {
        id: String::new(),
        name: host.to_string(),
        host: host.to_string(),
        port: AGENT_PORT,
        fingerprint: fingerprint.to_string(),
        ssh_saved: false,
    };
    let (mut conn, hello) = Connection::open(&probe, id).await?;
    match conn.request(Request::WhoAmI).await {
        Ok(keel_proto::Response::Me(_)) => {
            return Ok(ServerRecord {
                id: hello.server_id,
                ..probe
            });
        }
        Err(ConnectError::NotPaired) => {}
        Ok(_) => {
            return Err(ConnectError::Io(
                "The server sent an unexpected reply. Update the app or the server agent."
                    .to_string(),
            ));
        }
        Err(e) => return Err(e),
    }
    drop(conn);
    pair(host, AGENT_PORT, fingerprint, token, device_name, id).await
}
