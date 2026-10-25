//! Commands the UI calls. Errors are plain-language strings.

use std::sync::{Arc, Mutex};

use keel_client::onboarding::{
    AgentArtifacts, InstallOptions, OnboardingEvent, SshAuth, SshTarget, generate_ssh_keypair,
    run_onboarding,
};
use std::time::Duration;

use keel_client::{Connection, DeviceIdentity, Keychain, OsKeychain, ServerStore, pair_or_confirm};
use keel_proto::{ErrorCode, PairingCode, Request, Response, UserInfo};
use serde::Deserialize;
use tauri::{AppHandle, Emitter, Manager, State};
use zeroize::Zeroizing;

use crate::poller::{AppView, Poller, ServerView};

/// Everything the commands share, managed by Tauri.
pub struct AppState {
    pub store: Mutex<ServerStore>,
    pub identity: Arc<DeviceIdentity>,
    pub poller: Arc<Poller>,
    pub artifacts: Arc<AgentArtifacts>,
    /// The generated SSH private key, held until onboarding finishes.
    pub pending_key: Mutex<Option<Zeroizing<String>>>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OnboardAuth {
    GeneratedKey,
    PrivateKey {
        pem: String,
        passphrase: Option<String>,
    },
    Password {
        password: String,
    },
}

#[derive(Deserialize)]
pub struct OnboardRequest {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: OnboardAuth,
    pub options: InstallOptions,
}

impl std::fmt::Debug for OnboardAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OnboardAuth::GeneratedKey => f.write_str("GeneratedKey"),
            OnboardAuth::PrivateKey { .. } => f.write_str("PrivateKey { .. }"),
            OnboardAuth::Password { .. } => f.write_str("Password { .. }"),
        }
    }
}

impl std::fmt::Debug for OnboardRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnboardRequest")
            .field("name", &self.name)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("auth", &self.auth)
            .finish_non_exhaustive()
    }
}

const STORE_ERROR: &str =
    "Couldn't save the server list on this device. Check that the disk isn't full and try again.";

fn device_name() -> String {
    gethostname::gethostname().to_string_lossy().into_owned()
}

#[tauri::command]
pub async fn list_servers(state: State<'_, AppState>) -> Result<Vec<ServerView>, String> {
    Ok(state.poller.views())
}

#[tauri::command]
pub async fn server_status(id: String, state: State<'_, AppState>) -> Result<ServerView, String> {
    state
        .poller
        .view(&id)
        .ok_or_else(|| "This server isn't in your list any more.".to_string())
}

#[tauri::command]
pub async fn list_apps(state: State<'_, AppState>) -> Result<Vec<AppView>, String> {
    Ok(state.poller.apps())
}

/// Returns the public line to add to the server's `authorized_keys`.
#[tauri::command]
pub async fn generate_ssh_key(state: State<'_, AppState>) -> Result<String, String> {
    let (private, public) = generate_ssh_keypair();
    *state.pending_key.lock().unwrap() = Some(Zeroizing::new(private));
    Ok(public)
}

#[tauri::command]
pub async fn start_onboarding(
    req: OnboardRequest,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let auth = match req.auth {
        OnboardAuth::GeneratedKey => {
            let pem = state.pending_key.lock().unwrap().clone().ok_or_else(|| {
                "The generated key is no longer available. Generate a new key and try again."
                    .to_string()
            })?;
            SshAuth::PrivateKey {
                pem,
                passphrase: None,
            }
        }
        OnboardAuth::PrivateKey { pem, passphrase } => SshAuth::PrivateKey {
            pem: Zeroizing::new(pem),
            passphrase: passphrase.map(Zeroizing::new),
        },
        OnboardAuth::Password { password } => SshAuth::Password(Zeroizing::new(password)),
    };
    let target = SshTarget {
        host: req.host,
        port: req.port,
        user: req.user,
        auth,
    };
    let (name, options) = (req.name, req.options);
    let identity = Arc::clone(&state.identity);
    let artifacts = Arc::clone(&state.artifacts);

    let (tx, mut rx) = tokio::sync::mpsc::channel::<OnboardingEvent>(64);
    let forward_app = app.clone();
    let succeeded = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let succeeded_fwd = Arc::clone(&succeeded);
    let forwarder = tauri::async_runtime::spawn(async move {
        while let Some(ev) = rx.recv().await {
            let ev = match ev {
                OnboardingEvent::Done(rec) => {
                    let state = forward_app.state::<AppState>();
                    let saved = state.store.lock().unwrap().upsert(rec.clone());
                    match saved {
                        Ok(()) => {
                            succeeded_fwd.store(true, std::sync::atomic::Ordering::SeqCst);
                            state.poller.start(rec.clone());
                            OnboardingEvent::Done(rec)
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "saving server failed");
                            OnboardingEvent::Failed(STORE_ERROR.to_string())
                        }
                    }
                }
                other => other,
            };
            let _ = forward_app.emit("onboarding://event", ev);
        }
    });
    tauri::async_runtime::spawn(async move {
        let _ = run_onboarding(
            target,
            name,
            device_name(),
            options,
            &artifacts,
            &identity,
            &OsKeychain,
            tx,
        )
        .await;
        let _ = forwarder.await;
        // Keep the key after a failure so the user can retry without
        // re-authorizing it; drop it once onboarding succeeded.
        if succeeded.load(std::sync::atomic::Ordering::SeqCst) {
            *app.state::<AppState>().pending_key.lock().unwrap() = None;
        }
    });
    Ok(())
}

#[tauri::command]
pub async fn pair_with_code(
    code: String,
    name: String,
    state: State<'_, AppState>,
) -> Result<ServerView, String> {
    let code = PairingCode::parse(&code).map_err(|e| e.to_string())?;
    let mut rec = pair_or_confirm(
        &code.host,
        code.port,
        &code.fingerprint,
        &code.token,
        &device_name(),
        &state.identity,
    )
    .await
    .map_err(|e| e.to_string())?;
    rec.name = name;
    state
        .store
        .lock()
        .unwrap()
        .upsert(rec.clone())
        .map_err(|e| {
            tracing::warn!(error = %e, "saving server failed");
            STORE_ERROR.to_string()
        })?;
    let id = rec.id.clone();
    state.poller.start(rec);
    state
        .poller
        .view(&id)
        .ok_or_else(|| "The server was added, but couldn't be read back. Restart the app.".into())
}

#[tauri::command]
pub async fn remove_server(id: String, state: State<'_, AppState>) -> Result<(), String> {
    state.store.lock().unwrap().remove(&id).map_err(|e| {
        tracing::warn!(error = %e, "removing server failed");
        STORE_ERROR.to_string()
    })?;
    state.poller.stop(&id);
    if let Err(e) = OsKeychain.delete(&format!("ssh:{id}")) {
        tracing::warn!(error = %e, "keychain delete failed");
    }
    Ok(())
}

/// Users of one server, for the server page. A refusal (the role may not
/// manage users) is reported as `None`, not as an error.
#[tauri::command]
pub async fn list_users(
    id: String,
    state: State<'_, AppState>,
) -> Result<Option<Vec<UserInfo>>, String> {
    let record = state
        .store
        .lock()
        .unwrap()
        .list()
        .iter()
        .find(|r| r.id == id)
        .cloned()
        .ok_or_else(|| "This server isn't in your list any more.".to_string())?;
    let unreachable = || "Couldn't reach this server to load its users.".to_string();
    let (mut conn, _) = Connection::open(&record, &state.identity)
        .await
        .map_err(|e| {
            tracing::debug!(error = %e, "list users: connect failed");
            unreachable()
        })?;
    let resp = tokio::time::timeout(Duration::from_secs(5), conn.request(Request::ListUsers))
        .await
        .map_err(|_| unreachable())?
        .map_err(|e| {
            tracing::debug!(error = %e, "list users failed");
            unreachable()
        })?;
    match resp {
        Response::Users(users) => Ok(Some(users)),
        Response::Error {
            code: ErrorCode::Forbidden,
            ..
        } => Ok(None),
        _ => Err(unreachable()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_never_contains_secrets() {
        let password = OnboardAuth::Password {
            password: "hunter2-secret".into(),
        };
        let key = OnboardAuth::PrivateKey {
            pem: "-----BEGIN PRIVATE KEY-----abc".into(),
            passphrase: Some("pass-secret".into()),
        };
        let req = OnboardRequest {
            name: "edge".into(),
            host: "h".into(),
            port: 22,
            user: "root".into(),
            auth: OnboardAuth::Password {
                password: "hunter2-secret".into(),
            },
            options: InstallOptions::default(),
        };
        for text in [
            format!("{password:?}"),
            format!("{key:?}"),
            format!("{req:?}"),
        ] {
            for secret in ["hunter2-secret", "pass-secret", "BEGIN PRIVATE KEY", "abc"] {
                assert!(!text.contains(secret), "{text} leaked {secret}");
            }
        }
    }
}
