//! Per-server reachability polling.
//!
//! `next` is the pure state machine. `Poller` runs one task per server: it
//! keeps one connection open, asks for status and apps every 5 seconds, and
//! publishes the full server list whenever any view changes.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use keel_client::{ConnectError, Connection, DeviceIdentity, ServerRecord};
use keel_proto::{AppSummary, Request, Response, ServerStatus};
use serde::Serialize;
use tauri::async_runtime::{JoinHandle, spawn};
use tokio::time::{MissedTickBehavior, interval, timeout};

pub const POLL_INTERVAL: Duration = Duration::from_secs(5);
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Consecutive failures before a server is shown as unreachable.
const FAILURES_UNTIL_UNREACHABLE: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reachability {
    Online,
    Unreachable,
    /// The server's identity no longer matches the pinned fingerprint.
    Untrusted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollState {
    pub reachability: Reachability,
    pub failures: u32,
    pub last_seen: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollOutcome {
    Success,
    Failure,
    Mismatch,
}

impl PollState {
    /// A server that has not answered yet.
    pub fn new() -> PollState {
        PollState {
            reachability: Reachability::Unreachable,
            failures: 0,
            last_seen: None,
        }
    }
}

impl Default for PollState {
    fn default() -> Self {
        Self::new()
    }
}

/// Advance the state by one poll. `Untrusted` is terminal.
pub fn next(state: PollState, outcome: PollOutcome, now: i64) -> PollState {
    if state.reachability == Reachability::Untrusted {
        return state;
    }
    match outcome {
        PollOutcome::Success => PollState {
            reachability: Reachability::Online,
            failures: 0,
            last_seen: Some(now),
        },
        PollOutcome::Failure => {
            let failures = state.failures.saturating_add(1);
            PollState {
                reachability: if failures >= FAILURES_UNTIL_UNREACHABLE {
                    Reachability::Unreachable
                } else {
                    state.reachability
                },
                failures,
                ..state
            }
        }
        PollOutcome::Mismatch => PollState {
            reachability: Reachability::Untrusted,
            ..state
        },
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ServerView {
    pub id: String,
    pub name: String,
    pub host: String,
    pub reachability: Reachability,
    pub last_seen: Option<i64>,
    pub status: Option<ServerStatus>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppView {
    pub server_id: String,
    pub server_name: String,
    pub app: AppSummary,
}

struct Entry {
    record: ServerRecord,
    state: PollState,
    status: Option<ServerStatus>,
    apps: Vec<AppSummary>,
    task: Option<JoinHandle<()>>,
}

impl Entry {
    fn view(&self) -> ServerView {
        ServerView {
            id: self.record.id.clone(),
            name: self.record.name.clone(),
            host: self.record.host.clone(),
            reachability: self.state.reachability,
            last_seen: self.state.last_seen,
            status: self.status.clone(),
        }
    }
}

type Emit = Arc<dyn Fn(Vec<ServerView>) + Send + Sync>;

/// All known servers and their polling tasks.
pub struct Poller {
    entries: Mutex<Vec<Entry>>,
    identity: Arc<DeviceIdentity>,
    emit: Emit,
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl Poller {
    pub fn new(identity: Arc<DeviceIdentity>, emit: Emit) -> Arc<Poller> {
        Arc::new(Poller {
            entries: Mutex::new(Vec::new()),
            identity,
            emit,
        })
    }

    pub fn views(&self) -> Vec<ServerView> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .map(Entry::view)
            .collect()
    }

    pub fn view(&self, id: &str) -> Option<ServerView> {
        let entries = self.entries.lock().unwrap();
        entries.iter().find(|e| e.record.id == id).map(Entry::view)
    }

    pub fn apps(&self) -> Vec<AppView> {
        let entries = self.entries.lock().unwrap();
        entries
            .iter()
            .flat_map(|e| {
                e.apps.iter().map(|a| AppView {
                    server_id: e.record.id.clone(),
                    server_name: e.record.name.clone(),
                    app: a.clone(),
                })
            })
            .collect()
    }

    /// Start (or restart) polling a server.
    pub fn start(self: &Arc<Self>, record: ServerRecord) {
        let id = record.id.clone();
        self.stop_quietly(&id);
        {
            let mut entries = self.entries.lock().unwrap();
            entries.push(Entry {
                record: record.clone(),
                state: PollState::new(),
                status: None,
                apps: Vec::new(),
                task: None,
            });
        }
        let me = Arc::clone(self);
        let handle = spawn(async move { me.run(record).await });
        if let Some(e) = self
            .entries
            .lock()
            .unwrap()
            .iter_mut()
            .find(|e| e.record.id == id)
        {
            e.task = Some(handle);
        }
        self.publish();
    }

    /// Stop polling a server and forget it.
    pub fn stop(&self, id: &str) {
        self.stop_quietly(id);
        self.publish();
    }

    fn stop_quietly(&self, id: &str) {
        let mut entries = self.entries.lock().unwrap();
        if let Some(pos) = entries.iter().position(|e| e.record.id == id)
            && let Some(task) = entries.remove(pos).task
        {
            task.abort();
        }
    }

    fn publish(&self) {
        (self.emit)(self.views());
    }

    /// Apply a poll result for `id`; publish if the view changed.
    fn record_poll(
        &self,
        id: &str,
        outcome: PollOutcome,
        data: Option<(ServerStatus, Vec<AppSummary>)>,
    ) {
        let changed = {
            let mut entries = self.entries.lock().unwrap();
            let Some(e) = entries.iter_mut().find(|e| e.record.id == id) else {
                return;
            };
            let before = e.view();
            e.state = next(e.state, outcome, now_secs());
            if let Some((status, apps)) = data {
                e.status = Some(status);
                e.apps = apps;
            }
            if e.state.reachability == Reachability::Untrusted {
                e.status = None;
                e.apps.clear();
            }
            e.view() != before
        };
        if changed {
            self.publish();
        }
    }

    async fn run(self: Arc<Self>, record: ServerRecord) {
        let mut conn: Option<Connection> = None;
        let mut ticker = interval(POLL_INTERVAL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if conn.is_none() {
                match Connection::open(&record, &self.identity).await {
                    Ok((c, _)) => conn = Some(c),
                    Err(ConnectError::FingerprintMismatch { .. }) => {
                        self.record_poll(&record.id, PollOutcome::Mismatch, None);
                        return;
                    }
                    Err(e) => {
                        tracing::debug!(server = %record.id, error = %e, "connect failed");
                        self.record_poll(&record.id, PollOutcome::Failure, None);
                        continue;
                    }
                }
            }
            let Some(c) = conn.as_mut() else { continue };
            match poll_once(c).await {
                Ok(data) => self.record_poll(&record.id, PollOutcome::Success, Some(data)),
                Err(e) => {
                    tracing::debug!(server = %record.id, error = %e, "poll failed");
                    // A failed or timed-out request poisons the connection.
                    conn = None;
                    self.record_poll(&record.id, PollOutcome::Failure, None);
                }
            }
        }
    }
}

async fn request(conn: &mut Connection, req: Request) -> Result<Response, String> {
    match timeout(REQUEST_TIMEOUT, conn.request(req)).await {
        Ok(Ok(resp)) => Ok(resp),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("request timed out".to_string()),
    }
}

async fn poll_once(conn: &mut Connection) -> Result<(ServerStatus, Vec<AppSummary>), String> {
    let status = match request(conn, Request::ServerStatus).await? {
        Response::Status(s) => s,
        other => return Err(format!("unexpected reply to status: {other:?}")),
    };
    let apps = match request(conn, Request::ListApps).await? {
        Response::Apps(a) => a,
        other => return Err(format!("unexpected reply to list apps: {other:?}")),
    };
    Ok((status, apps))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn online(now: i64) -> PollState {
        next(PollState::new(), PollOutcome::Success, now)
    }

    #[test]
    fn one_failure_stays_online() {
        let s = next(online(100), PollOutcome::Failure, 105);
        assert_eq!(s.reachability, Reachability::Online);
        assert_eq!(s.failures, 1);
        assert_eq!(s.last_seen, Some(100));
    }

    #[test]
    fn two_failures_unreachable_keeps_last_seen() {
        let s = next(online(100), PollOutcome::Failure, 105);
        let s = next(s, PollOutcome::Failure, 110);
        assert_eq!(s.reachability, Reachability::Unreachable);
        assert_eq!(s.last_seen, Some(100));
    }

    #[test]
    fn recovers_after_restart() {
        let s = next(online(100), PollOutcome::Failure, 105);
        let s = next(s, PollOutcome::Failure, 110);
        assert_eq!(s.reachability, Reachability::Unreachable);
        let s = next(s, PollOutcome::Failure, 115);
        assert_eq!(s.reachability, Reachability::Unreachable);
        let s = next(s, PollOutcome::Success, 120);
        assert_eq!(s.reachability, Reachability::Online);
        assert_eq!(s.failures, 0);
        assert_eq!(s.last_seen, Some(120));
    }

    #[test]
    fn new_server_is_unreachable_until_first_success() {
        let s = PollState::new();
        assert_eq!(s.reachability, Reachability::Unreachable);
        assert_eq!(s.last_seen, None);
        let s = next(s, PollOutcome::Failure, 5);
        assert_eq!(s.reachability, Reachability::Unreachable);
    }

    #[test]
    fn mismatch_is_untrusted_and_terminal() {
        let s = next(online(100), PollOutcome::Mismatch, 105);
        assert_eq!(s.reachability, Reachability::Untrusted);
        assert_eq!(s.last_seen, Some(100));
        for outcome in [PollOutcome::Success, PollOutcome::Failure] {
            let t = next(s, outcome, 110);
            assert_eq!(t, s);
        }
    }
}
