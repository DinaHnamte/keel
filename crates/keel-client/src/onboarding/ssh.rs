//! A small SSH client for onboarding: connect, learn the host key, sign in,
//! and run commands with optional stdin.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use russh::client::{self, Handle};
use russh::keys::ssh_key::LineEnding;
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::time::{Instant, sleep, timeout};

use super::install::{ExecOutput, Remote};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// Package installs can be slow on small servers.
const EXEC_TIMEOUT: Duration = Duration::from_secs(600);
/// Command output kept per stream; the rest is dropped.
const MAX_OUTPUT: usize = 1 << 20;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SshAuth {
    PrivateKey {
        pem: String,
        passphrase: Option<String>,
    },
    Password(String),
}

impl std::fmt::Debug for SshAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SshAuth::PrivateKey { .. } => f.write_str("PrivateKey(..)"),
            SshAuth::Password(_) => f.write_str("Password(..)"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshTarget {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: SshAuth,
}

/// A fresh Ed25519 key for Keel: (OpenSSH private key, `authorized_keys` line
/// ending in `keel@<device>`).
pub fn generate_ssh_keypair() -> (String, String) {
    let device = gethostname::gethostname().to_string_lossy().into_owned();
    generate_ssh_keypair_for(&device)
}

fn generate_ssh_keypair_for(device: &str) -> (String, String) {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    SystemRandom::new()
        .fill(&mut seed[..])
        .expect("the OS random number generator is available");
    let mut key = PrivateKey::from(Ed25519Keypair::from_seed(&seed));
    let device: String = device
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .collect();
    let device = if device.is_empty() {
        "device".into()
    } else {
        device
    };
    key.set_comment(format!("keel@{device}"));
    let private = key
        .to_openssh(LineEnding::LF)
        .expect("an Ed25519 key encodes")
        .to_string();
    let public = key
        .public_key()
        .to_openssh()
        .expect("an Ed25519 public key encodes");
    (private, public)
}

/// OpenSSH-style fingerprint, e.g. `SHA256:abc...` (base64, no padding).
fn host_key_fingerprint(key: &PublicKeyOrCertificate) -> String {
    match key {
        PublicKeyOrCertificate::PublicKey { key, .. } => key.fingerprint(HashAlg::Sha256),
        PublicKeyOrCertificate::Certificate(c) => c.public_key().fingerprint(HashAlg::Sha256),
    }
    .to_string()
}

struct Client {
    host_key: Arc<Mutex<Option<String>>>,
}

impl client::Handler for Client {
    type Error = russh::Error;

    /// Trust on first use: the key is recorded and shown to the person, and
    /// saved with the credentials when they are kept.
    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        *self.host_key.lock().unwrap() = Some(host_key_fingerprint(key));
        Ok(true)
    }
}

pub struct SshSession {
    handle: Handle<Client>,
    host: String,
    /// The SSH server's host key fingerprint.
    pub host_key: String,
}

impl SshSession {
    /// Open the transport and learn the host key, without signing in.
    pub async fn connect(host: &str, port: u16) -> Result<SshSession> {
        let host_key = Arc::new(Mutex::new(None));
        let config = Arc::new(client::Config {
            keepalive_interval: Some(Duration::from_secs(15)),
            ..Default::default()
        });
        let handler = Client {
            host_key: host_key.clone(),
        };
        let unreachable = || {
            anyhow!(
                "Couldn't connect to {host} on port {port}. Check the address and SSH port, and that the server is running."
            )
        };
        let handle = match timeout(
            CONNECT_TIMEOUT,
            client::connect(config, (host, port), handler),
        )
        .await
        {
            Ok(Ok(h)) => h,
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "ssh connect failed");
                return Err(unreachable());
            }
            Err(_) => return Err(unreachable()),
        };
        let host_key = host_key.lock().unwrap().take().ok_or_else(unreachable)?;
        Ok(SshSession {
            handle,
            host: host.to_string(),
            host_key,
        })
    }

    pub async fn authenticate(&mut self, user: &str, auth: &SshAuth) -> Result<()> {
        let refused = || {
            anyhow!(
                "The server didn't accept the sign-in for {user}. Check the user name and the key or password."
            )
        };
        let result = match auth {
            SshAuth::PrivateKey { pem, passphrase } => {
                let key = russh::keys::decode_secret_key(pem, passphrase.as_deref()).map_err(|e| {
                    tracing::debug!(error = %e, "could not decode private key");
                    anyhow!(
                        "The private key couldn't be read. Check it's an OpenSSH private key and that the passphrase is right."
                    )
                })?;
                let hash = self.handle.best_supported_rsa_hash().await?.flatten();
                self.handle
                    .authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(key), hash))
                    .await
            }
            SshAuth::Password(p) => self.handle.authenticate_password(user, p).await,
        };
        match result {
            Ok(r) if r.success() => Ok(()),
            Ok(_) => Err(refused()),
            Err(e) => {
                tracing::debug!(error = %e, "ssh authentication error");
                Err(refused())
            }
        }
    }

    async fn run(&self, cmd: &str, stdin: Option<&[u8]>) -> Result<ExecOutput> {
        let channel = self.handle.channel_open_session().await?;
        let (mut rd, wr) = channel.split();
        wr.exec(true, cmd).await?;
        let write = async {
            if let Some(bytes) = stdin {
                wr.data_bytes(bytes.to_vec()).await?;
            }
            wr.eof().await
        };
        let read = async {
            let (mut code, mut out, mut err) = (None, Vec::new(), Vec::new());
            while let Some(msg) = rd.wait().await {
                match msg {
                    ChannelMsg::Data { data } => append(&mut out, &data),
                    ChannelMsg::ExtendedData { data, ext: 1 } => append(&mut err, &data),
                    ChannelMsg::ExitStatus { exit_status } => {
                        code = Some(i32::try_from(exit_status).unwrap_or(-1))
                    }
                    ChannelMsg::ExitSignal { .. } => code = Some(-1),
                    ChannelMsg::Close => break,
                    _ => {}
                }
            }
            (code, out, err)
        };
        let (written, (code, out, err)) = tokio::join!(write, read);
        let code = code.context("the command ended without an exit status")?;
        // A command that exits early (say, sudo refusing) closes stdin first;
        // its exit status is the useful error then.
        if let Err(e) = written
            && code == 0
        {
            return Err(e.into());
        }
        Ok((
            code,
            String::from_utf8_lossy(&out).into_owned(),
            String::from_utf8_lossy(&err).into_owned(),
        ))
    }

    pub async fn close(self) {
        let _ = self
            .handle
            .disconnect(Disconnect::ByApplication, "", "en")
            .await;
    }
}

fn append(buf: &mut Vec<u8>, data: &[u8]) {
    let room = MAX_OUTPUT.saturating_sub(buf.len());
    buf.extend_from_slice(&data[..data.len().min(room)]);
}

impl Remote for SshSession {
    async fn exec(&mut self, cmd: &str, stdin: Option<&[u8]>) -> Result<ExecOutput> {
        match timeout(EXEC_TIMEOUT, self.run(cmd, stdin)).await {
            Ok(r) => r,
            Err(_) => Err(anyhow!("the command timed out")),
        }
    }

    async fn reachable(&mut self, port: u16, within: Duration) -> bool {
        let deadline = Instant::now() + within;
        loop {
            let attempt = timeout(
                Duration::from_secs(2),
                TcpStream::connect((self.host.as_str(), port)),
            );
            if let Ok(Ok(_)) = attempt.await {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            sleep(Duration::from_millis(500)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keypair_round_trips_and_names_device() {
        let (private, public) = generate_ssh_keypair_for("dinah's laptop");
        assert!(private.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(public.starts_with("ssh-ed25519 "), "{public}");
        assert!(public.ends_with(" keel@dinahslaptop"), "{public}");
        let key = russh::keys::decode_secret_key(&private, None).unwrap();
        assert_eq!(key.public_key().to_openssh().unwrap(), public);
        let (other, _) = generate_ssh_keypair_for("x");
        assert_ne!(private, other);
    }

    #[test]
    fn auth_debug_hides_secrets() {
        let a = SshAuth::Password("hunter2".into());
        assert!(!format!("{a:?}").contains("hunter2"));
    }
}
