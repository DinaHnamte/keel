//! Pinned mutual-TLS connection to an agent.
//!
//! The agent's certificate is self-signed, so there is no CA to trust.
//! Instead the record holds the agent's public-key fingerprint, learned when
//! the server was added, and the handshake fails unless the agent presents
//! exactly that key. The pin is never updated here: a changed key is an error
//! the person has to resolve by removing and re-adding the server.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use keel_proto::{
    ErrorCode, FrameError, PROTOCOL_VERSION, Request, Response, read_frame, spki_fingerprint,
    write_frame,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, ring};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::identity::DeviceIdentity;
use crate::servers::ServerRecord;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloInfo {
    pub protocol: u16,
    pub agent_version: String,
    pub server_id: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("{0}")]
    Unreachable(String),
    #[error(
        "This server's identity has changed since you added it. If you reinstalled the agent, remove and re-add the server. Otherwise someone may be intercepting the connection."
    )]
    FingerprintMismatch { expected: String, got: String },
    #[error(
        "This server speaks a different version of Keel than this app. Update the app or the server agent so they match."
    )]
    UnsupportedProtocol,
    #[error(
        "This device isn't paired with the server yet. Add the server again with a new pairing code."
    )]
    NotPaired,
    /// The agent refused, with its own plain-language explanation.
    #[error("{0}")]
    Rejected(String),
    /// The agent returned an error other than a pairing rejection.
    #[error("{0}")]
    Agent(String),
    #[error("{0}")]
    Io(String),
}

/// Accepts only the agent key we pinned. Hostname, CA and expiry are ignored:
/// the key is the identity. Handshake signatures are still verified, so the
/// peer must hold the private key for the pinned certificate.
#[derive(Debug)]
struct PinnedVerifier {
    expected: String,
    provider: Arc<CryptoProvider>,
    /// Fingerprint of the certificate the peer presented, if it did not match.
    observed: Mutex<Option<String>>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let got = spki_fingerprint(end_entity).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        if got == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            *self.observed.lock().unwrap() = Some(got);
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub struct Connection {
    tls: TlsStream<TcpStream>,
    /// Set while a request is in flight and left set after any I/O, decode
    /// or timeout failure, or if the request future was dropped. A late reply
    /// could otherwise be read as the answer to the next request, so a broken
    /// connection is never reused: callers reconnect.
    broken: bool,
    io_timeout: Duration,
}

fn unreachable_msg(host: &str, port: u16) -> String {
    format!(
        "Couldn't reach {host}:{port}. Check that the server is running and the address is right."
    )
}

impl Connection {
    /// Connect, verify the pinned fingerprint, and complete the Hello exchange.
    pub async fn open(
        rec: &ServerRecord,
        id: &DeviceIdentity,
    ) -> Result<(Connection, HelloInfo), ConnectError> {
        let (host, port) = (rec.host.as_str(), rec.port);
        let tcp = match timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port))).await {
            Ok(Ok(s)) => s,
            Ok(Err(_)) | Err(_) => {
                return Err(ConnectError::Unreachable(unreachable_msg(host, port)));
            }
        };

        let provider = Arc::new(ring::default_provider());
        let verifier = Arc::new(PinnedVerifier {
            expected: rec.fingerprint.clone(),
            provider: provider.clone(),
            observed: Mutex::new(None),
        });
        let cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| tls_setup_error())?
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_client_auth_cert(
                vec![CertificateDer::from(id.cert_der.clone())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(id.key_der.to_vec())),
            )
            .map_err(|_| tls_setup_error())?;

        // The name is required by the API but never checked.
        let name = ServerName::try_from("keel-agent").expect("static name is valid");
        let handshake = TlsConnector::from(Arc::new(cfg)).connect(name, tcp);
        let tls = match timeout(IO_TIMEOUT, handshake).await {
            Ok(Ok(t)) => t,
            Ok(Err(e)) => {
                let observed = verifier.observed.lock().unwrap().take();
                return Err(match observed {
                    Some(got) => ConnectError::FingerprintMismatch {
                        expected: rec.fingerprint.clone(),
                        got,
                    },
                    None => ConnectError::Io(format!(
                        "Couldn't set up a secure connection to {host}:{port} ({e})."
                    )),
                });
            }
            Err(_) => {
                return Err(ConnectError::Io(
                    "The server didn't finish setting up a secure connection. Try again, and check the agent is running."
                        .to_string(),
                ));
            }
        };

        let mut conn = Connection {
            tls,
            broken: false,
            io_timeout: IO_TIMEOUT,
        };
        let hello = conn
            .request(Request::Hello {
                protocol: PROTOCOL_VERSION,
                client_version: env!("CARGO_PKG_VERSION").to_string(),
            })
            .await;
        match hello {
            Ok(Response::HelloOk {
                protocol,
                agent_version,
                server_id,
            }) => Ok((
                conn,
                HelloInfo {
                    protocol,
                    agent_version,
                    server_id,
                },
            )),
            Ok(Response::Error {
                code: ErrorCode::UnsupportedProtocol,
                ..
            }) => Err(ConnectError::UnsupportedProtocol),
            Ok(Response::Error { message, .. }) => Err(ConnectError::Rejected(message)),
            Ok(_) => Err(ConnectError::Io(
                "The server sent an unexpected reply. Update the app or the server agent."
                    .to_string(),
            )),
            Err(e) => Err(e),
        }
    }

    /// Override the per-request timeout (tests).
    #[doc(hidden)]
    pub fn set_io_timeout(&mut self, d: Duration) {
        self.io_timeout = d;
    }

    /// Send one request and read its response. `NotPaired` becomes an error;
    /// other agent errors come back as `Ok(Response::Error { .. })`. After any
    /// failure the connection is unusable and later calls fail immediately.
    pub async fn request(&mut self, req: Request) -> Result<Response, ConnectError> {
        if self.broken {
            return Err(lost());
        }
        // Poisoned until the exchange completes: if this future is dropped
        // mid-flight (an outer timeout or select), a late reply may still be
        // on the wire, so the connection must not be reused.
        self.broken = true;
        let io = async {
            write_frame(&mut self.tls, &req).await.map_err(|_| lost())?;
            read_frame::<_, Response>(&mut self.tls)
                .await
                .map_err(|e| match e {
                    FrameError::Io(_) => lost(),
                    FrameError::Malformed | FrameError::TooLarge => not_understood(),
                })
        };
        let result = match timeout(self.io_timeout, io).await {
            Ok(r) => r,
            Err(_) => Err(ConnectError::Io(
                "The server stopped responding. Check your connection and try again.".to_string(),
            )),
        };
        if result.is_ok() {
            self.broken = false;
        }
        match result {
            Ok(Response::Error {
                code: ErrorCode::NotPaired,
                ..
            }) => Err(ConnectError::NotPaired),
            other => other,
        }
    }
}

fn not_understood() -> ConnectError {
    ConnectError::Io(
        "The server sent a reply this app doesn't understand. Update the app and the agent to the latest version."
            .to_string(),
    )
}

fn tls_setup_error() -> ConnectError {
    ConnectError::Io(
        "Couldn't prepare a secure connection on this device. Restart the app and try again."
            .to_string(),
    )
}

fn lost() -> ConnectError {
    ConnectError::Io(
        "The connection to the server was lost. Check your connection and try again.".to_string(),
    )
}

/// Pair this device with a server whose fingerprint came from the pairing code.
pub async fn pair(
    host: &str,
    port: u16,
    fingerprint: &str,
    token: &str,
    display_name: &str,
    id: &DeviceIdentity,
) -> Result<ServerRecord, ConnectError> {
    let probe = ServerRecord {
        id: String::new(),
        name: host.to_string(),
        host: host.to_string(),
        port,
        fingerprint: fingerprint.to_string(),
        ssh_saved: false,
    };
    let (mut conn, hello) = Connection::open(&probe, id).await?;
    let resp = conn
        .request(Request::Pair {
            token: token.to_string(),
            display_name: display_name.to_string(),
        })
        .await?;
    match resp {
        Response::Paired { .. } => Ok(ServerRecord {
            id: hello.server_id,
            ..probe
        }),
        Response::Error {
            code: ErrorCode::BadToken | ErrorCode::TokenExpired,
            message,
        } => Err(ConnectError::Rejected(message)),
        Response::Error { message, .. } => Err(ConnectError::Agent(message)),
        _ => Err(ConnectError::Io(
            "The server sent an unexpected reply. Update the app or the server agent.".to_string(),
        )),
    }
}
