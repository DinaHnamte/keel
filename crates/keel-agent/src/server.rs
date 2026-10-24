//! The agent's network listener: mutual TLS, connection limits, and the
//! per-connection request loop.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
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

/// Connection limits. The defaults are the production values.
#[derive(Debug, Clone)]
pub struct Limits {
    /// New connections allowed per source IP within `rate_window`.
    pub rate_max: usize,
    pub rate_window: Duration,
    /// Concurrent connections across all peers.
    pub max_conns: usize,
    /// TLS handshake plus first frame.
    pub handshake_timeout: Duration,
    /// Longest wait for the next request (and for a response to be written).
    pub idle_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            rate_max: 30,
            rate_window: Duration::from_secs(60),
            max_conns: 64,
            handshake_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(120),
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

/// Bind `cfg.listen` and serve until `shutdown` completes.
pub async fn run(cfg: AgentConfig, clock: Clock, shutdown: impl Future<Output = ()>) -> Result<()> {
    let listener = TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("could not listen on {}", cfg.listen))?;
    serve(listener, cfg, clock, shutdown).await
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
        if !rate.allow(ip, Instant::now()) {
            tracing::warn!(%ip, "too many new connections from one address; dropped");
            continue; // dropping `tcp` closes it before any TLS
        }
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            tracing::warn!(%ip, "connection limit reached; dropped");
            continue;
        };
        let shared = shared.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let _permit = permit;
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
            Ok(found) => found.map(|(user, projects)| Principal {
                role: user.role,
                projects,
            }),
            Err(e) => {
                tracing::error!(error = %e, "user lookup failed");
                send(tls, &error(ErrorCode::Internal, MSG_INTERNAL), idle).await?;
                continue;
            }
        };
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
}
