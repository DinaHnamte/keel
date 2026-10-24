//! Runs a real agent in-process and connects with the client core.

use std::net::SocketAddr;

use keel_agent::config::AgentConfig;
use keel_agent::init::init;
use keel_agent::server::{serve, system_clock};
use keel_client::{
    ConnectError, Connection, DeviceIdentity, MemoryKeychain, ServerRecord, ServerStore, pair,
};
use keel_proto::{Request, Response};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

struct TestAgent {
    addr: SocketAddr,
    fingerprint: String,
    token: String,
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
    tokio::spawn(serve(listener, cfg, system_clock(), async {
        let _ = rx.await;
    }));
    TestAgent {
        addr,
        fingerprint: out.fingerprint,
        token: out.pairing_code.token,
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
    // Bind then drop to get a port nobody listens on.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
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
