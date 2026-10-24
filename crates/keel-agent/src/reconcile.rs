//! Desired-state reconciliation: converge reality on startup and periodically.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, interval};

use crate::store::Store;

/// What a reconciler changed, in plain words.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    pub changed: Vec<String>,
}

pub trait Reconciler: Send {
    fn name(&self) -> &'static str;
    fn reconcile(&self, store: &Store) -> Result<Report>;
}

/// Keeps the data directory and TLS key files private to the agent user.
pub struct DataDirReconciler {
    pub data_dir: PathBuf,
}

/// Set `path` to `mode` if it differs; record the change.
fn ensure_mode(path: &Path, mode: u32, report: &mut Report) -> Result<()> {
    let current = std::fs::metadata(path)
        .with_context(|| format!("reading {}", path.display()))?
        .permissions()
        .mode()
        & 0o7777;
    if current != mode {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .with_context(|| format!("setting mode on {}", path.display()))?;
        report
            .changed
            .push(format!("Set {} to mode {mode:04o}", path.display()));
    }
    Ok(())
}

fn ensure_dir(path: &Path, report: &mut Report) -> Result<()> {
    if !path.is_dir() {
        std::fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
        report.changed.push(format!("Created {}", path.display()));
    }
    ensure_mode(path, 0o700, report)
}

impl Reconciler for DataDirReconciler {
    fn name(&self) -> &'static str {
        "data-dir"
    }

    fn reconcile(&self, _store: &Store) -> Result<Report> {
        let mut report = Report::default();
        ensure_dir(&self.data_dir, &mut report)?;
        let tls = self.data_dir.join("tls");
        ensure_dir(&tls, &mut report)?;
        let key = tls.join("agent.key");
        if key.exists() {
            ensure_mode(&key, 0o600, &mut report)?;
        }
        Ok(report)
    }
}

/// Run every reconciler now, then again each `every`. A failing reconciler is
/// logged and the rest still run.
pub fn spawn_reconcile_loop(
    store: Store,
    reconcilers: Vec<Box<dyn Reconciler>>,
    every: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = interval(every);
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            for r in &reconcilers {
                match r.reconcile(&store) {
                    Ok(report) => {
                        for c in &report.changed {
                            tracing::info!(reconciler = r.name(), "{c}");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(reconciler = r.name(), error = %format!("{e:#}"), "reconcile failed");
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn mode(p: &std::path::Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn data_dir_reconciler_fixes_modes() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        let tls = data.join("tls");
        std::fs::create_dir_all(&tls).unwrap();
        let key = tls.join("agent.key");
        std::fs::write(&key, b"k").unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&tls, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();

        let r = DataDirReconciler {
            data_dir: data.clone(),
        };
        let store = Store::open_in_memory().unwrap();
        let report = r.reconcile(&store).unwrap();
        assert_eq!(mode(&data), 0o700);
        assert_eq!(mode(&tls), 0o700);
        assert_eq!(mode(&key), 0o600);
        assert_eq!(report.changed.len(), 3, "{:?}", report.changed);
        assert!(
            report
                .changed
                .contains(&format!("Set {} to mode 0700", tls.display()))
        );

        // Already correct: nothing to report.
        assert!(r.reconcile(&store).unwrap().changed.is_empty());
    }

    #[test]
    fn data_dir_reconciler_creates_missing_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("fresh");
        let r = DataDirReconciler {
            data_dir: data.clone(),
        };
        let report = r.reconcile(&Store::open_in_memory().unwrap()).unwrap();
        assert_eq!(mode(&data), 0o700);
        assert_eq!(mode(&data.join("tls")), 0o700);
        assert!(!report.changed.is_empty());
    }

    struct Failing;
    impl Reconciler for Failing {
        fn name(&self) -> &'static str {
            "failing"
        }
        fn reconcile(&self, _: &Store) -> anyhow::Result<Report> {
            anyhow::bail!("boom")
        }
    }

    struct Counting(Arc<AtomicUsize>);
    impl Reconciler for Counting {
        fn name(&self) -> &'static str {
            "counting"
        }
        fn reconcile(&self, _: &Store) -> anyhow::Result<Report> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(Report::default())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn failing_reconciler_does_not_block_others() {
        let n = Arc::new(AtomicUsize::new(0));
        let h = spawn_reconcile_loop(
            Store::open_in_memory().unwrap(),
            vec![Box::new(Failing), Box::new(Counting(n.clone()))],
            Duration::from_secs(60),
        );
        // First pass runs immediately.
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(n.load(Ordering::SeqCst), 1);
        // And again every interval.
        tokio::time::sleep(Duration::from_secs(61)).await;
        assert_eq!(n.load(Ordering::SeqCst), 2);
        h.abort();
    }

    #[test]
    fn systemd_unit_has_required_directives() {
        let unit = include_str!("../dist/keel-agent.service");
        for d in [
            "Description=Keel agent",
            "After=network-online.target",
            "Wants=network-online.target",
            "[Install]",
            "WantedBy=multi-user.target",
            "Type=simple",
            "User=keel",
            "ExecStart=/usr/local/bin/keel-agent run",
            "Restart=always",
            "RestartSec=2",
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "ReadWritePaths=/var/lib/keel",
            "PrivateTmp=yes",
            "ProtectHome=yes",
            "MemoryMax=64M",
        ] {
            assert!(unit.lines().any(|l| l.trim() == d), "unit is missing {d}");
        }
    }
}
