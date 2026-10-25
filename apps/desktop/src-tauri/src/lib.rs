pub mod commands;
pub mod poller;

use std::sync::{Arc, Mutex};

use keel_client::onboarding::AgentArtifacts;
use keel_client::{DeviceIdentity, OsKeychain, ServerStore};
use tauri::path::BaseDirectory;
use tauri::{Emitter, Manager};

use commands::AppState;
use poller::Poller;

/// Read `agent/<name>` and its `.sig` from the app resources. Anything missing
/// or malformed leaves that architecture unavailable.
fn load_artifact(app: &tauri::App, name: &str) -> Option<(Vec<u8>, [u8; 64])> {
    let path = |rel: String| app.path().resolve(rel, BaseDirectory::Resource).ok();
    let bin = std::fs::read(path(format!("agent/{name}"))?).ok()?;
    let sig = std::fs::read(path(format!("agent/{name}.sig"))?).ok()?;
    Some((bin, sig.try_into().ok()?))
}

pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            let store = ServerStore::load(&dir)?;
            let identity =
                Arc::new(DeviceIdentity::load_or_create(&OsKeychain).map_err(|e| e.to_string())?);
            let handle = app.handle().clone();
            let poller = Poller::new(
                Arc::clone(&identity),
                Arc::new(move |views| {
                    let _ = handle.emit("servers://changed", views);
                }),
            );
            for rec in store.list() {
                poller.start(rec.clone());
            }
            let artifacts = AgentArtifacts {
                x86_64: load_artifact(app, "keel-agent-x86_64"),
                aarch64: load_artifact(app, "keel-agent-aarch64"),
            };
            app.manage(AppState {
                store: Mutex::new(store),
                identity,
                poller,
                artifacts: Arc::new(artifacts),
                pending_key: Mutex::new(None),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::list_servers,
            commands::server_status,
            commands::list_apps,
            commands::generate_ssh_key,
            commands::start_onboarding,
            commands::pair_with_code,
            commands::remove_server,
            commands::list_users,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Keel");
}
