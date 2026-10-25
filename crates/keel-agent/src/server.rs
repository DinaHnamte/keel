//! The agent's network listener: mutual TLS, connection limits, and the
//! per-connection request loop.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use keel_proto::{
    ErrorCode, FrameError, PROTOCOL_VERSION, Principal, Request, Response, negotiate, read_frame,
    write_frame,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use crate::config::AgentConfig;
use crate::handlers::{
    self, MSG_INTERNAL, MSG_MALFORMED, MSG_TOO_LARGE, MSG_UNSUPPORTED_PROTOCOL, error,
};
use crate::reconcile::{DataDirReconciler, Reconciler, spawn_reconcile_loop};
use crate::store::Store;
use crate::tls::{load_or_create_identity, peer_fingerprint, server_config};

/// Unix seconds. Injected so tests can move time.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

pub fn system_clock() -> Clock {
    Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    })
}

const MAX_FAILED_PAIRS: u32 = 3;

/// Connection limits. The defaults are the production values.
#[derive(Debug, Clone)]
pub struct Limits {
    /// New connections allowed per source IP within `rate_window`.
    pub rate_max: usize,
    pub rate_window: Duration,
    /// Concurrent connections across all peers.
    pub max_conns: usize,
    /// Concurrent connections per source address (IPv6 by /64).
    pub max_conns_per_ip: usize,
    /// TLS handshake plus first frame.
    pub handshake_timeout: Duration,
    /// Longest wait for the next request (and for a response to be written).
    pub idle_timeout: Duration,
    /// Number of connections currently being served (observable by tests).
    pub active: Arc<AtomicUsize>,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            rate_max: 30,
            rate_window: Duration::from_secs(60),
            max_conns: 64,
            max_conns_per_ip: 8,
            handshake_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(120),
            active: Arc::new(AtomicUsize::new(0)),
        }
    }
}

/// Limiter key: IPv4 by full address, IPv6 by its /64 prefix (one customer
/// usually holds a whole /64, so per-address limits would be trivial to dodge).
fn ip_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let mut o = v6.octets();
            o[8..].fill(0);
            IpAddr::V6(o.into())
        }
        v4 => v4,
    }
}

/// Concurrent connections per limiter key; a slot is released on drop.
#[derive(Clone, Default)]
struct IpSlots(Arc<Mutex<HashMap<IpAddr, usize>>>);

struct ActiveGuard(Arc<AtomicUsize>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct IpSlot {
    slots: IpSlots,
    key: IpAddr,
}

impl IpSlots {
    fn acquire(&self, key: IpAddr, max: usize) -> Option<IpSlot> {
        let mut m = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let n = m.entry(key).or_insert(0);
        if *n >= max {
            return None;
        }
        *n += 1;
        Some(IpSlot {
            slots: self.clone(),
            key,
        })
    }
}

impl Drop for IpSlot {
    fn drop(&mut self) {
        let mut m = self.slots.0.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(n) = m.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.key);
            }
        }
    }
}

/// Rolling-window per-IP connection counter. Entries are removed once their
/// last connection leaves the window, and a sweep runs at most once per window
/// so the map is bounded by the accept rate over one window.
struct RateLimiter {
    max: usize,
    window: Duration,
    hits: HashMap<IpAddr, VecDeque<Instant>>,
    last_sweep: Instant,
}

impl RateLimiter {
    fn new(max: usize, window: Duration) -> Self {
        RateLimiter {
            max,
            window,
            hits: HashMap::new(),
            last_sweep: Instant::now(),
        }
    }

    /// Record an attempt from `ip`; false if it exceeds the limit (and is then
    /// not recorded, so a flood cannot grow the map).
    fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        if now.duration_since(self.last_sweep) >= self.window {
            let window = self.window;
            self.hits.retain(|_, q| {
                q.retain(|t| now.duration_since(*t) < window);
                !q.is_empty()
            });
            self.last_sweep = now;
        }
        let q = self.hits.entry(ip).or_default();
        while q
            .front()
            .is_some_and(|t| now.duration_since(*t) >= self.window)
        {
            q.pop_front();
        }
        if q.len() >= self.max {
            return false;
        }
        q.push_back(now);
        true
    }
}

/// How often the reconcile loop converges reality on the desired state.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(60);

/// Bind `cfg.listen` and serve until `shutdown` completes.
pub async fn run(cfg: AgentConfig, clock: Clock, shutdown: impl Future<Output = ()>) -> Result<()> {
    let listener = TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("could not listen on {}", cfg.listen))?;
    // Keep the data directory private, now and every minute. The loop uses
    // its own connection so the server's critical sections stay short.
    std::fs::create_dir_all(&cfg.data_dir)
        .with_context(|| format!("could not create {}", cfg.data_dir.display()))?;
    let store = Store::open(&cfg.data_dir.join("keel.db"))?;
    let reconcilers: Vec<Box<dyn Reconciler>> = vec![Box::new(DataDirReconciler {
        data_dir: cfg.data_dir.clone(),
    })];
    let reconcile = spawn_reconcile_loop(store, reconcilers, RECONCILE_INTERVAL);
    let result = serve(listener, cfg, clock, shutdown).await;
    reconcile.abort();
    result
}

pub async fn serve(
    listener: TcpListener,
    cfg: AgentConfig,
    clock: Clock,
    shutdown: impl Future<Output = ()>,
) -> Result<()> {
    serve_with_limits(listener, cfg, clock, Limits::default(), shutdown).await
}

struct Shared {
    store: Store,
    data_dir: PathBuf,
    server_id: String,
    clock: Clock,
    limits: Limits,
}

pub async fn serve_with_limits(
    listener: TcpListener,
    cfg: AgentConfig,
    clock: Clock,
    limits: Limits,
    shutdown: impl Future<Output = ()>,
) -> Result<()> {
    let identity = load_or_create_identity(&cfg.data_dir.join("tls"))
        .context("could not load the TLS identity")?;
    let store = Store::open(&cfg.data_dir.join("keel.db"))?;
    let server_id = store.server_id()?;
    let acceptor = TlsAcceptor::from(server_config(&identity)?);
    tracing::info!(
        listen = %listener.local_addr()?,
        fingerprint = %identity.fingerprint,
        "agent listening"
    );

    let permits = Arc::new(Semaphore::new(limits.max_conns));
    let slots = IpSlots::default();
    let max_per_ip = limits.max_conns_per_ip;
    let mut rate = RateLimiter::new(limits.rate_max, limits.rate_window);
    let shared = Arc::new(Shared {
        store,
        data_dir: cfg.data_dir,
        server_id,
        clock,
        limits,
    });

    tokio::pin!(shutdown);
    loop {
        let (tcp, peer) = tokio::select! {
            () = &mut shutdown => {
                tracing::info!("shutting down");
                return Ok(());
            }
            r = listener.accept() => match r {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let ip = peer.ip().to_canonical();
        let key = ip_key(ip);
        if !rate.allow(key, Instant::now()) {
            tracing::warn!(%ip, "too many new connections from one address; dropped");
            continue; // dropping `tcp` closes it before any TLS
        }
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            tracing::warn!(%ip, "connection limit reached; dropped");
            continue;
        };
        let Some(ip_slot) = slots.acquire(key, max_per_ip) else {
            tracing::warn!(%ip, "too many open connections from one address; dropped");
            continue;
        };
        shared.limits.active.fetch_add(1, Ordering::SeqCst);
        let shared = shared.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ip_slot = ip_slot;
            let _active = ActiveGuard(shared.limits.active.clone());
            if let Err(e) =
                connection(tcp, SocketAddr::new(ip, peer.port()), acceptor, &shared).await
            {
                tracing::debug!(%ip, error = %e, "connection ended");
            }
        });
    }
}

/// Send a response, bounded by the idle timeout so a peer that never reads
/// cannot hold a slot.
async fn send<W: AsyncWrite + Unpin>(w: &mut W, resp: &Response, limit: Duration) -> Result<()> {
    timeout(limit, write_frame(w, resp))
        .await
        .context("write timed out")??;
    Ok(())
}

/// Reply to a framing failure where possible.
fn frame_error_response(e: &FrameError) -> Option<Response> {
    match e {
        FrameError::TooLarge => Some(error(ErrorCode::TooLarge, MSG_TOO_LARGE)),
        FrameError::Malformed => Some(error(ErrorCode::Malformed, MSG_MALFORMED)),
        FrameError::Io(_) => None,
    }
}

async fn close<S: AsyncWrite + Unpin>(s: &mut S) {
    let _ = timeout(Duration::from_secs(2), s.shutdown()).await;
}

async fn connection(
    tcp: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    sh: &Shared,
) -> Result<()> {
    let ip = peer.ip();
    let limits = &sh.limits;
    let first = timeout(limits.handshake_timeout, async {
        let mut tls = acceptor.accept(tcp).await.context("TLS handshake failed")?;
        let fp = peer_fingerprint(tls.get_ref().1).context("no client certificate")?;
        let req: Result<Request, FrameError> = read_frame(&mut tls).await;
        anyhow::Ok((tls, fp, req))
    })
    .await
    .context("handshake timed out")??;
    let (mut tls, fingerprint, first) = first;

    let result = session(&mut tls, &fingerprint, first, ip, sh).await;
    close(&mut tls).await;
    result
}

async fn session<S: AsyncRead + AsyncWrite + Unpin>(
    tls: &mut S,
    fingerprint: &str,
    first: Result<Request, FrameError>,
    ip: IpAddr,
    sh: &Shared,
) -> Result<()> {
    let idle = sh.limits.idle_timeout;
    // First frame must be a valid Hello.
    match first {
        Ok(Request::Hello { protocol, .. }) => match negotiate(protocol) {
            Ok(version) => {
                let resp = Response::HelloOk {
                    protocol: version.min(PROTOCOL_VERSION),
                    agent_version: env!("CARGO_PKG_VERSION").to_string(),
                    server_id: sh.server_id.clone(),
                };
                send(tls, &resp, idle).await?;
            }
            Err(code) => {
                send(tls, &error(code, MSG_UNSUPPORTED_PROTOCOL), idle).await?;
                return Ok(());
            }
        },
        Ok(_) => {
            send(tls, &error(ErrorCode::Malformed, MSG_MALFORMED), idle).await?;
            return Ok(());
        }
        Err(e) => {
            if let Some(resp) = frame_error_response(&e) {
                send(tls, &resp, idle).await?;
            }
            return Ok(());
        }
    }

    // Unpaired connections get no retries beyond this many failed Pair attempts.
    let mut failed_pairs = 0u32;
    loop {
        let req = match timeout(idle, read_frame::<_, Request>(tls)).await {
            Err(_) => return Ok(()), // idle
            Ok(Ok(req)) => req,
            Ok(Err(e)) => {
                if let Some(resp) = frame_error_response(&e) {
                    send(tls, &resp, idle).await?;
                }
                return Ok(());
            }
        };
        // Resolve on every request so a revoked key loses access immediately.
        let who = match sh.store.find_user_by_fingerprint(fingerprint) {
            Ok(found) => found.map(|(user, projects)| {
                let principal = Principal {
                    role: user.role,
                    projects,
                };
                (user, principal)
            }),
            Err(e) => {
                tracing::error!(error = %e, "user lookup failed");
                send(tls, &error(ErrorCode::Internal, MSG_INTERNAL), idle).await?;
                continue;
            }
        };
        let is_pair = matches!(req, Request::Pair { .. });
        let resp = handlers::handle(
            &sh.store,
            &sh.data_dir,
            who.as_ref(),
            fingerprint,
            req,
            ip,
            (sh.clock)(),
        );
        send(tls, &resp, idle).await?;
        if who.is_none() {
            // An unpaired device may only pair: close after a stray request, or
            // after too many failed attempts (each one writes an audit row).
            match &resp {
                Response::Error {
                    code: ErrorCode::NotPaired,
                    ..
                } => return Ok(()),
                Response::Error { .. } if is_pair => {
                    failed_pairs += 1;
                    if failed_pairs >= MAX_FAILED_PAIRS {
                        return Ok(());
                    }
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_rolls_and_prunes() {
        let mut rl = RateLimiter::new(2, Duration::from_secs(60));
        let t0 = Instant::now();
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(rl.allow(a, t0));
        assert!(rl.allow(a, t0));
        assert!(!rl.allow(a, t0));
        assert!(rl.allow(b, t0), "limit is per address");
        // A rejected attempt is not recorded, so the window still ends on time.
        let t1 = t0 + Duration::from_secs(61);
        assert!(rl.allow(a, t1));
        // The sweep removed b, which had nothing left in the window.
        assert_eq!(rl.hits.len(), 1);
    }

    #[test]
    fn ipv6_keyed_by_64_prefix_ipv4_by_address() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:bbbb::2".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(ip_key(a), ip_key(b));
        assert_ne!(ip_key(a), ip_key(c));
        let v4a: IpAddr = "10.0.0.1".parse().unwrap();
        let v4b: IpAddr = "10.0.0.2".parse().unwrap();
        assert_ne!(ip_key(v4a), ip_key(v4b));
        let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        assert_eq!(ip_key(mapped), v4a);
        let mut rl = RateLimiter::new(1, Duration::from_secs(60));
        let t = Instant::now();
        assert!(rl.allow(ip_key(a), t));
        assert!(!rl.allow(ip_key(b), t), "same /64 shares one budget");
    }

    #[test]
    fn ip_slots_release_on_drop() {
        let slots = IpSlots::default();
        let k: IpAddr = "10.0.0.1".parse().unwrap();
        let a = slots.acquire(k, 2).unwrap();
        let _b = slots.acquire(k, 2).unwrap();
        assert!(slots.acquire(k, 2).is_none());
        drop(a);
        assert!(slots.acquire(k, 2).is_some());
    }
}
