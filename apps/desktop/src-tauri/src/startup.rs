//! Opening the device identity and the server list at launch. Nothing here
//! panics: a problem becomes a message the window shows.

use std::path::Path;

use keel_client::{DeviceIdentity, Keychain, ServerStore};
use serde::Serialize;

pub const KEYCHAIN_ERROR: &str = "Keel couldn't open your system keychain. Unlock it or install a keychain service, then restart Keel.";

pub const STORE_UNREADABLE: &str = "Keel couldn't open the folder where it keeps your servers. Check that your home folder is readable and the disk isn't full, then restart Keel.";

pub fn corrupt_notice(kept_as: &str) -> String {
    format!(
        "Keel couldn't read your saved servers, so it started fresh. The old file was kept as {kept_as}."
    )
}

/// What the window shows before anything else.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct StartupStatus {
    /// Keel can't work at all: the window shows only this message.
    pub fatal: Option<String>,
    /// Shown once above the fleet board.
    pub notice: Option<String>,
}

pub struct Opened {
    pub identity: DeviceIdentity,
    pub store: ServerStore,
}

/// Open the identity first (without it nothing works, and no file storage is
/// ever used in its place), then the server list, recovering from a corrupt
/// `servers.json` by moving it aside.
pub fn open(dir: Option<&Path>, kc: &dyn Keychain, now: u64) -> (Option<Opened>, StartupStatus) {
    let identity = match DeviceIdentity::load_or_create(kc) {
        Ok(id) => id,
        Err(e) => {
            tracing::error!(error = %e, "device identity unavailable");
            return (None, fatal(KEYCHAIN_ERROR));
        }
    };
    let Some(dir) = dir else {
        return (None, fatal(STORE_UNREADABLE));
    };
    match ServerStore::load_or_recover(dir, now) {
        Ok((store, moved)) => {
            if let Some(name) = &moved {
                tracing::warn!(kept_as = %name, "servers.json was unreadable; started empty");
            }
            let status = StartupStatus {
                fatal: None,
                notice: moved.as_deref().map(corrupt_notice),
            };
            (Some(Opened { identity, store }), status)
        }
        Err(e) => {
            tracing::error!(error = %e, "server list unavailable");
            (None, fatal(STORE_UNREADABLE))
        }
    }
}

fn fatal(msg: &str) -> StartupStatus {
    StartupStatus {
        fatal: Some(msg.to_string()),
        notice: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keel_client::MemoryKeychain;

    type R<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
    struct LockedKeychain;
    impl Keychain for LockedKeychain {
        fn get(&self, _: &str) -> R<Option<Vec<u8>>> {
            Err("no secret service".into())
        }
        fn set(&self, _: &str, _: &[u8]) -> R<()> {
            Err("no secret service".into())
        }
        fn delete(&self, _: &str) -> R<()> {
            Err("no secret service".into())
        }
    }

    #[test]
    fn corrupt_server_list_starts_fresh_with_a_notice() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("servers.json"), b"not json").unwrap();
        let (opened, status) = open(Some(dir.path()), &MemoryKeychain::new(), 42);
        assert!(opened.unwrap().store.list().is_empty());
        assert_eq!(status.fatal, None);
        assert_eq!(
            status.notice.as_deref(),
            Some(
                "Keel couldn't read your saved servers, so it started fresh. The old file was kept as servers.json.corrupt-42."
            )
        );
        assert!(dir.path().join("servers.json.corrupt-42").is_file());
    }

    #[test]
    fn healthy_start_has_no_messages() {
        let dir = tempfile::tempdir().unwrap();
        let (opened, status) = open(Some(dir.path()), &MemoryKeychain::new(), 1);
        assert!(opened.is_some());
        assert_eq!(status, StartupStatus::default());
    }

    #[test]
    fn keychain_failure_is_fatal_and_writes_no_files() {
        let dir = tempfile::tempdir().unwrap();
        let (opened, status) = open(Some(dir.path()), &LockedKeychain, 1);
        assert!(opened.is_none());
        assert_eq!(status.fatal.as_deref(), Some(KEYCHAIN_ERROR));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn missing_data_dir_is_fatal() {
        let (opened, status) = open(None, &MemoryKeychain::new(), 1);
        assert!(opened.is_none());
        assert_eq!(status.fatal.as_deref(), Some(STORE_UNREADABLE));
    }
}
