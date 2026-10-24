//! Idle memory budget: the agent must stay under 25 MB RSS (spec section 1).
#![cfg(target_os = "linux")]

mod common;

use std::net::{SocketAddr, TcpListener};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::Client;
use keel_proto::{PairingCode, Request, Response};

const BUDGET: u64 = 25 * 1024 * 1024;

/// Kills the child on drop, so a panic never leaves an agent running.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn vm_rss_bytes(pid: u32) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let line = status
        .lines()
        .find(|l| l.starts_with("VmRSS:"))
        .expect("VmRSS line");
    let kb: u64 = line
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .expect("VmRSS value");
    kb * 1024
}

#[tokio::test]
async fn idle_rss_under_25mb() {
    let bin = env!("CARGO_BIN_EXE_keel-agent");
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let config = dir.path().join("agent.toml");
    std::fs::write(
        &config,
        format!(
            "listen = \"{addr}\"\ndata_dir = \"{}\"\n",
            data_dir.display()
        ),
    )
    .unwrap();

    let out = Command::new(bin)
        .args(["init", "--host", "127.0.0.1", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(out.status.success(), "init failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let code = stdout
        .lines()
        .find_map(|l| l.strip_prefix("pairing_code="))
        .expect("pairing_code line");
    let token = PairingCode::parse(code).unwrap().token;

    let child = Command::new(bin)
        .args(["run", "--config"])
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id();
    let _guard = KillOnDrop(child);

    let deadline = Instant::now() + Duration::from_secs(10);
    while std::net::TcpStream::connect(addr).is_err() {
        assert!(Instant::now() < deadline, "agent did not start listening");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // One paired client, connection kept open while we measure.
    let mut client = Client::connect_hello(addr).await;
    match client
        .request(&Request::Pair {
            token,
            display_name: "memory test".into(),
        })
        .await
    {
        Response::Paired { .. } => {}
        other => panic!("expected Paired, got {other:?}"),
    }

    tokio::time::sleep(Duration::from_secs(10)).await;
    let rss = vm_rss_bytes(pid);
    println!(
        "idle VmRSS: {rss} bytes ({:.2} MiB), budget {BUDGET}",
        rss as f64 / 1_048_576.0
    );
    assert!(rss < BUDGET, "idle RSS {rss} bytes is over the budget");
    drop(client);
}
