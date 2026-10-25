pub mod commands;
pub mod poller;
pub mod startup;

use std::sync::{Arc, Mutex};

use keel_client::OsKeychain;
use keel_client::onboarding::AgentArtifacts;
use tauri::path::BaseDirectory;
use tauri::{Emitter, Manager};

use commands::{AppState, Core};
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
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let dir = app.path().app_data_dir().ok();
            let (opened, status) = startup::open(dir.as_deref(), &OsKeychain, now);
            let core = opened.map(|o| {
                let identity = Arc::new(o.identity);
                let handle = app.handle().clone();
                let poller = Poller::new(
                    Arc::clone(&identity),
                    Arc::new(move |views| {
                        let _ = handle.emit("servers://changed", views);
                    }),
                );
                for rec in o.store.list() {
                    poller.start(rec.clone());
                }
                Core {
                    store: Mutex::new(o.store),
                    identity,
                    poller,
                }
            });
            let artifacts = AgentArtifacts {
                x86_64: load_artifact(app, "keel-agent-x86_64"),
                aarch64: load_artifact(app, "keel-agent-aarch64"),
            };
            app.manage(AppState {
                core,
                startup: Mutex::new(status),
                artifacts: Arc::new(artifacts),
                pending_key: Mutex::new(None),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::startup_status,
            commands::list_servers,
            commands::server_status,
            commands::list_apps,
            commands::generate_ssh_key,
            commands::pending_ssh_key,
            commands::start_onboarding,
            commands::pair_with_code,
            commands::remove_server,
            commands::list_users,
        ])
        .run(tauri::generate_context!())
        .unwrap_or_else(|e| {
            // The window could not be created at all, so there is nowhere
            // to show a message: report it and exit without a panic.
            eprintln!("Keel couldn't open its window: {e}");
            std::process::exit(1);
        });
}
