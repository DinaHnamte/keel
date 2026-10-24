mod common;

use std::time::Duration;

use common::{Agent, Client, Identity, T0};
use keel_agent::server::Limits;
use keel_agent::sysinfo::{
    parse_loadavg, parse_meminfo, parse_os_release, parse_uptime, parse_vmrss,
};
use keel_proto::{ErrorCode, MAX_FRAME, PROTOCOL_VERSION, Request, Response, Role};
use sha2::Digest;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// Poll until `n` connections are being served, or fail after a deadline.
async fn wait_for_accepts(agent: &Agent, n: usize) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while agent.open_connections() < n {
        assert!(
            std::time::Instant::now() < deadline,
            "server did not accept {n} connections in time"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn pair(token: &str, name: &str) -> Request {
    Request::Pair {
        token: token.into(),
        display_name: name.into(),
    }
}

fn expect_error(r: Response, code: ErrorCode) -> String {
    match r {
        Response::Error { code: c, message } => {
            assert_eq!(c, code, "message: {message}");
            message
        }
        other => panic!("expected {code:?}, got {other:?}"),
    }
}

#[tokio::test]
async fn hello_then_pair_then_whoami_is_owner() {
    let agent = Agent::start().await;
    let mut c = Client::connect(agent.addr).await;
    match c
        .request(&Request::Hello {
            protocol: PROTOCOL_VERSION,
            client_version: "test".into(),
        })
        .await
    {
        Response::HelloOk {
            protocol,
            agent_version,
            server_id,
        } => {
            assert_eq!(protocol, PROTOCOL_VERSION);
            assert!(!agent_version.is_empty());
            assert!(!server_id.is_empty());
        }
        other => panic!("{other:?}"),
    }
    let paired = c.request(&pair(&agent.token, "Dinah")).await;
    let user_id = match paired {
        Response::Paired { user_id, role } => {
            assert_eq!(role, Role::Owner);
            user_id
        }
        other => panic!("{other:?}"),
    };
    // The same connection continues as the new user.
    match c.request(&Request::WhoAmI).await {
        Response::Me(u) => {
            assert_eq!(u.id, user_id);
            assert_eq!(u.display_name, "Dinah");
            assert_eq!(u.role, Role::Owner);
            assert_eq!(u.key_fingerprint, c.fingerprint);
        }
        other => panic!("{other:?}"),
    }
    match c.request(&Request::ServerStatus).await {
        Response::Status(s) => {
            assert!(s.mem_total_bytes > 0);
            assert!(s.disk_total_bytes > 0);
            assert!(!s.os_pretty_name.is_empty());
            assert!(s.agent_rss_bytes > 0);
        }
        other => panic!("{other:?}"),
    }
    match c.request(&Request::ListUsers).await {
        Response::Users(u) => assert_eq!(u.len(), 1),
        other => panic!("{other:?}"),
    }
    match c.request(&Request::ListApps).await {
        Response::Apps(a) => assert!(a.is_empty()),
        other => panic!("{other:?}"),
    }
    // Pairing is audited.
    let n: i64 = rusqlite::Connection::open(agent.db_path())
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'pair' AND user_id = ?1 AND device = '127.0.0.1'",
            [user_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 1);
    agent.stop().await;
}

#[tokio::test]
async fn unpaired_client_gets_not_paired() {
    let agent = Agent::start().await;
    for req in [
        Request::WhoAmI,
        Request::ServerStatus,
        Request::ListApps,
        Request::ListUsers,
    ] {
        // Each stray request ends the connection, so use a fresh one.
        let mut c = Client::connect_hello(agent.addr).await;
        let m = expect_error(c.request(&req).await, ErrorCode::NotPaired);
        assert_eq!(m, "This device isn't paired with the server yet.");
    }
    agent.stop().await;
}

#[tokio::test]
async fn bad_token_rejected_and_audited() {
    let agent = Agent::start().await;
    let mut c = Client::connect_hello(agent.addr).await;
    let m = expect_error(
        c.request(&pair("not-a-real-token", "X")).await,
        ErrorCode::BadToken,
    );
    assert_eq!(m, "That pairing code isn't valid.");
    let n: i64 = rusqlite::Connection::open(agent.db_path())
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'pair_failed' AND user_id IS NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 1);
    // Still unpaired afterwards.
    expect_error(c.request(&Request::WhoAmI).await, ErrorCode::NotPaired);
    agent.stop().await;
}

#[tokio::test]
async fn pair_token_replay_rejected() {
    let agent = Agent::start().await;
    let mut a = Client::connect_hello(agent.addr).await;
    assert!(matches!(
        a.request(&pair(&agent.token, "First")).await,
        Response::Paired { .. }
    ));
    let mut b = Client::connect_hello(agent.addr).await;
    let m = expect_error(
        b.request(&pair(&agent.token, "Second")).await,
        ErrorCode::BadToken,
    );
    assert_eq!(m, "That pairing code isn't valid.");
    expect_error(b.request(&Request::WhoAmI).await, ErrorCode::NotPaired);
    agent.stop().await;
}

#[tokio::test]
async fn pair_token_expired_rejected() {
    let agent = Agent::start().await;
    agent.set_clock(T0 + 86_400 + 1);
    let mut c = Client::connect_hello(agent.addr).await;
    let m = expect_error(
        c.request(&pair(&agent.token, "Late")).await,
        ErrorCode::TokenExpired,
    );
    assert_eq!(m, "That pairing code has expired. Create a new one.");
    agent.stop().await;
}

#[tokio::test]
async fn newer_protocol_rejected_cleanly() {
    let agent = Agent::start().await;
    let mut c = Client::connect(agent.addr).await;
    let r = c
        .request(&Request::Hello {
            protocol: PROTOCOL_VERSION + 1,
            client_version: "future".into(),
        })
        .await;
    let m = expect_error(r, ErrorCode::UnsupportedProtocol);
    assert_eq!(
        m,
        "This app and the server agent are on incompatible versions. Update both to the latest version."
    );
    assert!(c.closed_within(2).await);
    agent.stop().await;
}

#[tokio::test]
async fn first_frame_not_hello_closes() {
    let agent = Agent::start().await;
    let mut c = Client::connect(agent.addr).await;
    let m = expect_error(c.request(&Request::WhoAmI).await, ErrorCode::Malformed);
    assert_eq!(m, "The request couldn't be understood.");
    assert!(c.closed_within(2).await);
    agent.stop().await;
}

#[tokio::test]
async fn second_hello_is_malformed() {
    let agent = Agent::start().await;
    let mut c = Client::connect_hello(agent.addr).await;
    let r = c
        .request(&Request::Hello {
            protocol: 1,
            client_version: "x".into(),
        })
        .await;
    expect_error(r, ErrorCode::Malformed);
    agent.stop().await;
}

#[tokio::test]
async fn oversize_frame_closes_without_crash() {
    let agent = Agent::start().await;
    let mut c = Client::connect_hello(agent.addr).await;
    // Header claims a body one byte over the cap; send no body.
    c.tls
        .write_all(&((MAX_FRAME as u32 + 1).to_be_bytes()))
        .await
        .unwrap();
    c.tls.flush().await.unwrap();
    assert!(c.closed_within(2).await);
    assert!(agent.is_running());
    // The agent still serves new connections.
    let mut d = Client::connect_hello(agent.addr).await;
    expect_error(d.request(&Request::WhoAmI).await, ErrorCode::NotPaired);
    agent.stop().await;
}

#[tokio::test]
async fn garbage_json_closes_without_crash() {
    let agent = Agent::start().await;
    let mut c = Client::connect_hello(agent.addr).await;
    let body = b"{not json";
    let mut buf = (body.len() as u32).to_be_bytes().to_vec();
    buf.extend_from_slice(body);
    c.tls.write_all(&buf).await.unwrap();
    c.tls.flush().await.unwrap();
    assert!(c.closed_within(2).await);
    assert!(agent.is_running());
    agent.stop().await;
}

#[tokio::test]
async fn viewer_cannot_list_users() {
    let agent = Agent::start().await;
    let id = Identity::fresh();
    let uid = agent.add_user(&id.fingerprint, Role::Viewer, "Vera");
    let mut c = Client::connect_as(agent.addr, &id).await;
    c.hello().await;
    // Viewer may see server status and who they are.
    assert!(matches!(c.request(&Request::WhoAmI).await, Response::Me(_)));
    assert!(matches!(
        c.request(&Request::ServerStatus).await,
        Response::Status(_)
    ));
    let m = expect_error(c.request(&Request::ListUsers).await, ErrorCode::Forbidden);
    assert_eq!(m, "Your role can't do this.");
    // The denial is audited against the user; the reads are not.
    let conn = rusqlite::Connection::open(agent.db_path()).unwrap();
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'forbidden:ListUsers' AND user_id = ?1",
            [uid],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 1);
    let total: i64 = conn
        .query_row("SELECT COUNT(*) FROM audit_log", [], |r| r.get(0))
        .unwrap();
    assert_eq!(total, 1, "read-only requests must not be audited");
    agent.stop().await;
}

#[tokio::test]
async fn list_apps_filters_by_project_membership() {
    let agent = Agent::start().await;
    let id = Identity::fresh();
    let uid = agent.add_user(&id.fingerprint, Role::Viewer, "Vera");
    {
        let conn = rusqlite::Connection::open(agent.db_path()).unwrap();
        conn.execute_batch(
            "INSERT INTO projects(id, name) VALUES (1, 'one'), (2, 'two');
             INSERT INTO apps(id, name, project_id, state) VALUES (1, 'alpha', 1, 'live'), (2, 'beta', 2, 'live');",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO project_members(project_id, user_id) VALUES (1, ?1)",
            [uid],
        )
        .unwrap();
    }
    let mut c = Client::connect_as(agent.addr, &id).await;
    c.hello().await;
    match c.request(&Request::ListApps).await {
        Response::Apps(a) => {
            assert_eq!(a.len(), 1);
            assert_eq!(a[0].name, "alpha");
        }
        other => panic!("{other:?}"),
    }
    agent.stop().await;
}

#[tokio::test]
async fn revoked_user_loses_access_on_open_connection() {
    let agent = Agent::start().await;
    let mut c = Client::connect_hello(agent.addr).await;
    assert!(matches!(
        c.request(&pair(&agent.token, "Dinah")).await,
        Response::Paired { .. }
    ));
    assert!(matches!(c.request(&Request::WhoAmI).await, Response::Me(_)));
    rusqlite::Connection::open(agent.db_path())
        .unwrap()
        .execute("DELETE FROM users", [])
        .unwrap();
    expect_error(c.request(&Request::WhoAmI).await, ErrorCode::NotPaired);
    agent.stop().await;
}

#[tokio::test]
async fn rate_limit_drops_31st_connection_in_a_minute() {
    // Production rate numbers; only the per-IP concurrency cap is lifted so
    // 30 simultaneous connections from 127.0.0.1 can be held open.
    let agent = Agent::start_with(Limits {
        max_conns_per_ip: 100,
        ..Limits::default()
    })
    .await;
    // 30 raw TCP connections are accepted (and then wait for a TLS hello).
    let mut held = Vec::new();
    for _ in 0..30 {
        held.push(TcpStream::connect(agent.addr).await.unwrap());
    }
    // Wait until the server has accepted all of them (it holds a TLS accept
    // for each, so the agent's connection count is what we poll).
    wait_for_accepts(&agent, 30).await;
    let mut over = TcpStream::connect(agent.addr).await.unwrap();
    use tokio::io::AsyncReadExt;
    let mut b = [0u8; 16];
    let r = tokio::time::timeout(Duration::from_secs(2), over.read(&mut b)).await;
    match r {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        other => panic!("31st connection should be dropped immediately, got {other:?}"),
    }
    // An accepted one is still open (no data, not closed).
    let r = tokio::time::timeout(Duration::from_millis(200), held[0].read(&mut b)).await;
    assert!(r.is_err(), "first connection must still be open");
    agent.stop().await;
}

#[tokio::test]
async fn rate_limit_is_per_ip_and_window_rolls() {
    let agent = Agent::start_with(Limits {
        rate_max: 2,
        rate_window: Duration::from_millis(400),
        ..Limits::default()
    })
    .await;
    let _a = TcpStream::connect(agent.addr).await.unwrap();
    let _b = TcpStream::connect(agent.addr).await.unwrap();
    wait_for_accepts(&agent, 2).await;
    let mut over = TcpStream::connect(agent.addr).await.unwrap();
    use tokio::io::AsyncReadExt;
    let mut buf = [0u8; 4];
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), over.read(&mut buf)).await,
        Ok(Ok(0)) | Ok(Err(_))
    ));
    // After the window passes a TLS client is served again.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut c = Client::connect_hello(agent.addr).await;
    expect_error(c.request(&Request::WhoAmI).await, ErrorCode::NotPaired);
    agent.stop().await;
}

#[tokio::test]
async fn connection_cap_drops_over_limit() {
    let agent = Agent::start_with(Limits {
        max_conns: 2,
        max_conns_per_ip: 100,
        ..Limits::default()
    })
    .await;
    let _a = TcpStream::connect(agent.addr).await.unwrap();
    let _b = TcpStream::connect(agent.addr).await.unwrap();
    wait_for_accepts(&agent, 2).await;
    let mut over = TcpStream::connect(agent.addr).await.unwrap();
    use tokio::io::AsyncReadExt;
    let mut buf = [0u8; 4];
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), over.read(&mut buf)).await,
        Ok(Ok(0)) | Ok(Err(_))
    ));
    agent.stop().await;
}

#[tokio::test]
async fn handshake_timeout_closes_silent_connection() {
    let agent = Agent::start_with(Limits {
        handshake_timeout: Duration::from_millis(300),
        ..Limits::default()
    })
    .await;
    let mut silent = TcpStream::connect(agent.addr).await.unwrap();
    use tokio::io::AsyncReadExt;
    let mut buf = [0u8; 4];
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(3), silent.read(&mut buf)).await,
        Ok(Ok(0)) | Ok(Err(_))
    ));
    // TLS ok but no Hello: also closed.
    let mut c = Client::connect(agent.addr).await;
    assert!(c.closed_within(3).await);
    agent.stop().await;
}

#[tokio::test]
async fn idle_timeout_closes_connection() {
    let agent = Agent::start_with(Limits {
        idle_timeout: Duration::from_millis(300),
        ..Limits::default()
    })
    .await;
    let mut c = Client::connect_hello(agent.addr).await;
    assert!(c.closed_within(3).await);
    agent.stop().await;
}

#[test]
fn parse_meminfo_used_is_total_minus_available() {
    let s = "MemTotal:        2048000 kB\nMemFree:          100000 kB\nMemAvailable:    1024000 kB\nBuffers: 5 kB\n";
    assert_eq!(parse_meminfo(s), (2_048_000 * 1024, 1_024_000 * 1024));
    assert_eq!(parse_meminfo(""), (0, 0));
}

#[test]
fn parse_loadavg_first_field() {
    assert_eq!(parse_loadavg("0.52 0.40 0.31 1/234 5678\n"), 0.52);
    assert_eq!(parse_loadavg("garbage"), 0.0);
}

#[test]
fn parse_uptime_whole_seconds() {
    assert_eq!(parse_uptime("12345.67 23456.78\n"), 12345);
    assert_eq!(parse_uptime(""), 0);
}

#[test]
fn parse_os_release_pretty_name_unquoted() {
    let s =
        "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nID=ubuntu\n";
    assert_eq!(parse_os_release(s), "Ubuntu 24.04.1 LTS");
    assert_eq!(
        parse_os_release("PRETTY_NAME='Debian GNU/Linux 12'\n"),
        "Debian GNU/Linux 12"
    );
    assert_eq!(parse_os_release("ID=x\n"), "Linux");
}

#[test]
fn parse_vmrss_kb_to_bytes() {
    let s = "Name:\tkeel-agent\nVmPeak:\t  9000 kB\nVmRSS:\t   1234 kB\nThreads:\t1\n";
    assert_eq!(parse_vmrss(s), 1234 * 1024);
    assert_eq!(parse_vmrss("Name: x\n"), 0);
}

#[tokio::test]
async fn unpaired_closed_after_three_failed_pairs() {
    let agent = Agent::start().await;
    let mut c = Client::connect_hello(agent.addr).await;
    for _ in 0..3 {
        expect_error(c.request(&pair("wrong", "X")).await, ErrorCode::BadToken);
    }
    assert!(c.closed_within(2).await);
    let n: i64 = rusqlite::Connection::open(agent.db_path())
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'pair_failed'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 3, "no audit row for the close itself");
    agent.stop().await;
}

#[tokio::test]
async fn unpaired_closed_after_not_paired() {
    let agent = Agent::start().await;
    let mut c = Client::connect_hello(agent.addr).await;
    expect_error(c.request(&Request::ListApps).await, ErrorCode::NotPaired);
    assert!(c.closed_within(2).await);
    agent.stop().await;
}

#[tokio::test]
async fn per_ip_concurrent_cap() {
    let agent = Agent::start().await;
    let mut held = Vec::new();
    for _ in 0..8 {
        held.push(TcpStream::connect(agent.addr).await.unwrap());
    }
    wait_for_accepts(&agent, 8).await;
    let mut ninth = TcpStream::connect(agent.addr).await.unwrap();
    use tokio::io::AsyncReadExt;
    let mut b = [0u8; 4];
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), ninth.read(&mut b)).await,
        Ok(Ok(0)) | Ok(Err(_))
    ));
    for h in &mut held {
        assert!(
            tokio::time::timeout(Duration::from_millis(100), h.read(&mut b))
                .await
                .is_err(),
            "the first eight stay open"
        );
    }
    // Releasing one frees a slot.
    held.pop();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let mut again = TcpStream::connect(agent.addr).await.unwrap();
        if tokio::time::timeout(Duration::from_millis(300), again.read(&mut b))
            .await
            .is_err()
        {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "slot never released");
    }
    agent.stop().await;
}

#[tokio::test]
async fn already_paired_device_pairing_again_does_not_burn_token() {
    let agent = Agent::start().await;
    let mut a = Client::connect_hello(agent.addr).await;
    assert!(matches!(
        a.request(&pair(&agent.token, "First")).await,
        Response::Paired { .. }
    ));
    // A second token, offered by the already-paired device.
    let token2 = "second-token";
    let hash: [u8; 32] = sha2::Sha256::digest(token2.as_bytes()).into();
    agent
        .store()
        .create_pairing_token(&hash, Role::Admin, T0 + 1000)
        .unwrap();
    let m = expect_error(a.request(&pair(token2, "Again")).await, ErrorCode::BadToken);
    assert_eq!(m, "This device is already paired with this server.");
    // The token still works for a different device.
    let mut b = Client::connect_hello(agent.addr).await;
    match b.request(&pair(token2, "Second")).await {
        Response::Paired { role, .. } => assert_eq!(role, Role::Admin),
        other => panic!("{other:?}"),
    }
    agent.stop().await;
}
