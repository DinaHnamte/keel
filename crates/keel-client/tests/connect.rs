//! Runs a real agent in-process and connects with the client core.

use std::net::SocketAddr;
use std::sync::Arc;

use keel_agent::config::AgentConfig;
use keel_agent::init::init;
use keel_agent::server::{serve, system_clock};
use keel_client::{
    ConnectError, Connection, DeviceIdentity, MemoryKeychain, ServerRecord, ServerStore, pair,
    pair_or_confirm,
};
use keel_proto::{Request, Response};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

struct TestAgent {
    addr: SocketAddr,
    fingerprint: String,
    token: String,
    cfg: AgentConfig,
    _dir: tempfile::TempDir,
    _shutdown: oneshot::Sender<()>,
}

async fn start_agent() -> TestAgent {
    let dir = tempfile::tempdir().unwrap();
    let cfg = AgentConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: dir.path().join("data"),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let out = init(&cfg, "127.0.0.1", now).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(serve(listener, cfg.clone(), system_clock(), async {
        let _ = rx.await;
    }));
    TestAgent {
        addr,
        fingerprint: out.fingerprint,
        token: out.pairing_code.token,
        cfg,
        _dir: dir,
        _shutdown: tx,
    }
}

fn identity() -> DeviceIdentity {
    DeviceIdentity::load_or_create(&MemoryKeychain::new()).unwrap()
}

#[tokio::test]
async fn connect_pinned_ok_then_status() {
    let agent = start_agent().await;
    let id = identity();
    let rec = pair(
        "127.0.0.1",
        agent.addr.port(),
        &agent.fingerprint,
        &agent.token,
        "Dinah's laptop",
        &id,
    )
    .await
    .unwrap();
    assert_eq!(rec.fingerprint, agent.fingerprint);
    assert_eq!(rec.host, "127.0.0.1");
    assert_eq!(rec.name, "127.0.0.1");
    assert!(!rec.ssh_saved);
    assert!(!rec.id.is_empty());

    let (mut conn, hello) = Connection::open(&rec, &id).await.unwrap();
    assert_eq!(hello.server_id, rec.id);
    match conn.request(Request::ServerStatus).await.unwrap() {
        Response::Status(s) => assert!(!s.hostname.is_empty()),
        other => panic!("expected status, got {other:?}"),
    }
}

#[tokio::test]
async fn connect_with_wrong_pin_refuses() {
    let agent = start_agent().await;
    let id = identity();
    let good = pair(
        "127.0.0.1",
        agent.addr.port(),
        &agent.fingerprint,
        &agent.token,
        "me",
        &id,
    )
    .await
    .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let mut store = ServerStore::load(dir.path()).unwrap();
    let wrong = identity().fingerprint;
    let bad = ServerRecord {
        fingerprint: wrong.clone(),
        ..good.clone()
    };
    store.upsert(bad.clone()).unwrap();

    let err = Connection::open(&bad, &id).await.err().unwrap();
    match err {
        ConnectError::FingerprintMismatch { expected, got } => {
            assert_eq!(expected, wrong);
            assert_eq!(got, agent.fingerprint);
        }
        other => panic!("expected mismatch, got {other:?}"),
    }
    // Never silently re-pinned.
    let reloaded = ServerStore::load(dir.path()).unwrap();
    assert_eq!(reloaded.list(), &[bad]);
}

#[tokio::test]
async fn pair_with_wrong_pin_refuses() {
    let agent = start_agent().await;
    let err = pair(
        "127.0.0.1",
        agent.addr.port(),
        &identity().fingerprint,
        &agent.token,
        "me",
        &identity(),
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(err, ConnectError::FingerprintMismatch { .. }));
}

#[tokio::test]
async fn pair_with_bad_token_is_rejected_in_plain_language() {
    let agent = start_agent().await;
    let err = pair(
        "127.0.0.1",
        agent.addr.port(),
        &agent.fingerprint,
        "not-the-token",
        "me",
        &identity(),
    )
    .await
    .err()
    .unwrap();
    match err {
        ConnectError::Rejected(m) => assert!(!m.is_empty()),
        other => panic!("expected Rejected, got {other:?}"),
    }
}

#[tokio::test]
async fn unpaired_device_gets_not_paired() {
    let agent = start_agent().await;
    let rec = ServerRecord {
        id: "x".into(),
        name: "x".into(),
        host: "127.0.0.1".into(),
        port: agent.addr.port(),
        fingerprint: agent.fingerprint.clone(),
        ssh_saved: false,
    };
    let (mut conn, _) = Connection::open(&rec, &identity()).await.unwrap();
    let err = conn.request(Request::ServerStatus).await.err().unwrap();
    assert!(matches!(err, ConnectError::NotPaired));
}

#[tokio::test]
async fn connect_to_closed_port_is_unreachable() {
    // Port 1 is privileged and nothing listens on it.
    let port = 1;
    let rec = ServerRecord {
        id: "x".into(),
        name: "x".into(),
        host: "127.0.0.1".into(),
        port,
        fingerprint: "aa".into(),
        ssh_saved: false,
    };
    let err = Connection::open(&rec, &identity()).await.err().unwrap();
    match err {
        ConnectError::Unreachable(m) => {
            assert!(m.contains(&format!("127.0.0.1:{port}")), "{m}");
            assert!(m.contains("Check that the server is running"), "{m}");
        }
        other => panic!("expected Unreachable, got {other:?}"),
    }
}

/// A pinned-TLS server that completes Hello and then answers every later
/// request only after `delay`, so the client sees a timeout and a late reply.
async fn slow_server(delay: std::time::Duration) -> (u16, String) {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec![])
        .unwrap()
        .self_signed(&kp)
        .unwrap();
    let fp = keel_proto::spki_fingerprint(cert.der()).unwrap();
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(cert.der().to_vec())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(kp.serialize_der())),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (tcp, _) = l.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.unwrap();
        let _: Request = keel_proto::read_frame(&mut tls).await.unwrap();
        let hello = Response::HelloOk {
            protocol: 1,
            agent_version: "t".into(),
            server_id: "slow".into(),
        };
        keel_proto::write_frame(&mut tls, &hello).await.unwrap();
        while let Ok(_req) = keel_proto::read_frame::<_, Request>(&mut tls).await {
            tokio::time::sleep(delay).await;
            let _ = keel_proto::write_frame(&mut tls, &hello).await;
        }
    });
    (port, fp)
}

#[tokio::test]
async fn request_after_failure_fails_fast() {
    let (port, fp) = slow_server(std::time::Duration::from_millis(300)).await;
    let rec = ServerRecord {
        id: "slow".into(),
        name: "slow".into(),
        host: "127.0.0.1".into(),
        port,
        fingerprint: fp,
        ssh_saved: false,
    };
    let (mut conn, _) = Connection::open(&rec, &identity()).await.unwrap();
    conn.set_io_timeout(std::time::Duration::from_millis(50));
    assert!(matches!(
        conn.request(Request::ServerStatus).await,
        Err(ConnectError::Io(_))
    ));
    // Let the late reply arrive; it must never be read as the next answer.
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    conn.set_io_timeout(std::time::Duration::from_secs(30));
    let r = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        conn.request(Request::ServerStatus),
    )
    .await
    .expect("must fail immediately, not hang");
    assert!(matches!(r, Err(ConnectError::Io(_))));
}

#[tokio::test]
async fn dropped_request_poisons_connection() {
    let (port, fp) = slow_server(std::time::Duration::from_millis(300)).await;
    let rec = ServerRecord {
        id: "slow".into(),
        name: "slow".into(),
        host: "127.0.0.1".into(),
        port,
        fingerprint: fp,
        ssh_saved: false,
    };
    let (mut conn, _) = Connection::open(&rec, &identity()).await.unwrap();
    // An outer timeout drops the request future mid-flight; the connection's
    // own timeout never fires.
    let dropped = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        conn.request(Request::ServerStatus),
    )
    .await;
    assert!(dropped.is_err(), "outer timeout should have fired");
    // Let the late reply arrive; it must never be read as the next answer.
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    let started = std::time::Instant::now();
    let r = conn.request(Request::ServerStatus).await;
    assert!(matches!(r, Err(ConnectError::Io(_))), "got {r:?}");
    assert!(started.elapsed() < std::time::Duration::from_millis(100));
}

/// A server removed from the app and added again with a new code: the device
/// is still an Owner on the agent, so the code path confirms instead of
/// failing with "already paired".
#[tokio::test]
async fn pairing_code_again_after_removal_confirms_owner() {
    let agent = start_agent().await;
    let id = identity();
    let port = agent.addr.port();
    let first = pair("127.0.0.1", port, &agent.fingerprint, &agent.token, "me", &id)
        .await
        .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let fresh = init(&agent.cfg, "127.0.0.1", now).unwrap().pairing_code.token;
    // Plain pairing refuses, and says what to do.
    let err = pair("127.0.0.1", port, &agent.fingerprint, &fresh, "me", &id)
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "This device is already paired with this server. Remove it from the app and add it again, or keep using it."
    );
    let again = pair_or_confirm("127.0.0.1", port, &agent.fingerprint, &fresh, "me", &id)
        .await
        .unwrap();
    assert_eq!(again, first);
}

#[tokio::test]
async fn pair_or_confirm_pairs_an_unpaired_device() {
    let agent = start_agent().await;
    let id = identity();
    let port = agent.addr.port();
    let rec = pair_or_confirm("127.0.0.1", port, &agent.fingerprint, &agent.token, "me", &id)
        .await
        .unwrap();
    let (_, hello) = Connection::open(&rec, &id).await.unwrap();
    assert_eq!(hello.server_id, rec.id);
}
