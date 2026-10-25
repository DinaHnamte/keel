//! Shared test helpers: a running agent on a temp data dir and a TLS client
//! with a fresh self-signed identity that pins nothing.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use keel_agent::config::AgentConfig;
use keel_agent::init::init;
use keel_agent::server::{Clock, Limits, serve_with_limits};
use keel_agent::store::Store;
use keel_proto::{
    PROTOCOL_VERSION, Request, Response, Role, read_frame, spki_fingerprint, write_frame,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

pub const T0: i64 = 1_000_000;

pub struct Agent {
    pub addr: SocketAddr,
    pub dir: tempfile::TempDir,
    pub agent_fingerprint: String,
    /// Owner pairing token issued by `init`.
    pub token: String,
    pub clock: Arc<AtomicI64>,
    active: Arc<std::sync::atomic::AtomicUsize>,
    shutdown: Option<oneshot::Sender<()>>,
    handle: Option<JoinHandle<anyhow::Result<()>>>,
}

impl Agent {
    pub async fn start() -> Agent {
        Self::start_with(Limits::default()).await
    }

    pub async fn start_with(limits: Limits) -> Agent {
        let active = limits.active.clone();
        let dir = tempfile::tempdir().unwrap();
        let cfg = AgentConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            data_dir: dir.path().join("data"),
        };
        let out = init(&cfg, "127.0.0.1", T0).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let clock = Arc::new(AtomicI64::new(T0));
        let c = clock.clone();
        let clock_fn: Clock = Arc::new(move || c.load(Ordering::SeqCst));
        let (tx, rx) = oneshot::channel::<()>();
        let handle = tokio::spawn(serve_with_limits(listener, cfg, clock_fn, limits, async {
            let _ = rx.await;
        }));
        Agent {
            addr,
            dir,
            agent_fingerprint: out.fingerprint,
            token: out.pairing_code.token,
            clock,
            active,
            shutdown: Some(tx),
            handle: Some(handle),
        }
    }

    /// Connections the server has accepted and is still serving.
    pub fn open_connections(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }

    pub fn db_path(&self) -> PathBuf {
        self.dir.path().join("data/keel.db")
    }

    pub fn store(&self) -> Store {
        Store::open(&self.db_path()).unwrap()
    }

    /// Insert a user with `role` for `fingerprint` directly through the store.
    pub fn add_user(&self, fingerprint: &str, role: Role, name: &str) -> i64 {
        let store = self.store();
        let token = format!("test-token-{fingerprint}");
        let hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        store
            .create_pairing_token(&hash, role, T0 + 86_400)
            .unwrap();
        store
            .redeem_pairing_token(&hash, fingerprint, name, T0)
            .unwrap()
            .id
    }

    pub fn set_clock(&self, now: i64) {
        self.clock.store(now, Ordering::SeqCst);
    }

    /// Stop the server and surface any error or panic from it.
    pub async fn stop(mut self) {
        let _ = self.shutdown.take().unwrap().send(());
        self.handle.take().unwrap().await.unwrap().unwrap();
    }

    /// Whether the server task is still running.
    pub fn is_running(&self) -> bool {
        self.handle.as_ref().is_some_and(|h| !h.is_finished())
    }
}

/// A client identity: self-signed cert and key, both DER.
#[derive(Clone)]
pub struct Identity {
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
    pub fingerprint: String,
}

impl Identity {
    pub fn fresh() -> Identity {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = rcgen::CertificateParams::new(vec![])
            .unwrap()
            .self_signed(&kp)
            .unwrap();
        let cert = cert.der().to_vec();
        let fingerprint = spki_fingerprint(&cert).unwrap();
        Identity {
            cert,
            key: kp.serialize_der(),
            fingerprint,
        }
    }
}

#[derive(Debug)]
struct AcceptAnyServer;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServer {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("tls12 unsupported".into()))
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            m,
            c,
            d,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub struct Client {
    pub tls: TlsStream<TcpStream>,
    pub fingerprint: String,
}

impl Client {
    /// TLS-connect with a fresh identity. Does not send Hello.
    pub async fn connect(addr: SocketAddr) -> Client {
        Self::connect_as(addr, &Identity::fresh()).await
    }

    pub async fn connect_as(addr: SocketAddr, id: &Identity) -> Client {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServer))
            .with_client_auth_cert(
                vec![CertificateDer::from(id.cert.clone())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(id.key.clone())),
            )
            .unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let name = ServerName::try_from("keel-agent").unwrap();
        let tls = TlsConnector::from(Arc::new(cfg))
            .connect(name, tcp)
            .await
            .unwrap();
        Client {
            tls,
            fingerprint: id.fingerprint.clone(),
        }
    }

    /// Connect and complete the Hello exchange.
    pub async fn connect_hello(addr: SocketAddr) -> Client {
        let mut c = Self::connect(addr).await;
        c.hello().await;
        c
    }

    pub async fn hello(&mut self) {
        match self
            .request(&Request::Hello {
                protocol: PROTOCOL_VERSION,
                client_version: "test".into(),
            })
            .await
        {
            Response::HelloOk { .. } => {}
            other => panic!("expected HelloOk, got {other:?}"),
        }
    }

    pub async fn send(&mut self, req: &Request) {
        write_frame(&mut self.tls, req).await.unwrap();
    }

    pub async fn recv(&mut self) -> Response {
        read_frame(&mut self.tls).await.unwrap()
    }

    pub async fn request(&mut self, req: &Request) -> Response {
        self.send(req).await;
        self.recv().await
    }

    /// True if the server closed the connection (EOF or reset) within `secs`.
    pub async fn closed_within(&mut self, secs: u64) -> bool {
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 1024];
        let fut = async {
            loop {
                match self.tls.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => continue,
                }
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(secs), fut)
            .await
            .is_ok()
    }
}
