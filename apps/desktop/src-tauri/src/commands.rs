//! Commands the UI calls. Errors are plain-language strings.

use std::sync::{Arc, Mutex};

use keel_client::onboarding::{
    AgentArtifacts, InstallOptions, OnboardingEvent, SshAuth, SshTarget, generate_ssh_keypair,
    run_onboarding,
};
use keel_client::{DeviceIdentity, Keychain, OsKeychain, ServerStore, pair};
use keel_proto::PairingCode;
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

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
pub struct OnboardRequest {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: OnboardAuth,
    pub options: InstallOptions,
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
    let forwarder = tauri::async_runtime::spawn(async move {
        while let Some(ev) = rx.recv().await {
            let ev = match ev {
                OnboardingEvent::Done(rec) => {
                    let state = forward_app.state::<AppState>();
                    let saved = state.store.lock().unwrap().upsert(rec.clone());
                    match saved {
                        Ok(()) => {
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
        // Success or failure, the generated key is no longer needed in memory.
        *app.state::<AppState>().pending_key.lock().unwrap() = None;
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
    let mut rec = pair(
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
    OsKeychain.delete(&format!("ssh:{id}")).map_err(|e| {
        tracing::warn!(error = %e, "keychain delete failed");
        "Couldn't remove this server's saved sign-in from your keychain. Unlock the keychain and try again.".to_string()
    })?;
    state.poller.stop(&id);
    state.store.lock().unwrap().remove(&id).map_err(|e| {
        tracing::warn!(error = %e, "removing server failed");
        STORE_ERROR.to_string()
    })
}
