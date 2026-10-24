//! Agent TLS identity and client fingerprinting.
//!
//! There is no certificate authority anywhere in Keel. The agent owns a
//! self-signed ECDSA P-256 certificate that the desktop pins by public-key
//! fingerprint, and users are identified by the fingerprint of their own
//! self-signed client certificate.

use anyhow::{Context, Result, bail};
use keel_proto::spki_fingerprint;
use rustls::DigitallySignedStruct;
use rustls::DistinguishedName;
use rustls::SignatureScheme;
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;
use std::sync::Arc;

const KEY_FILE: &str = "agent.key";
const CERT_FILE: &str = "agent.crt";
const VALIDITY_DAYS: i64 = 3650;

/// The agent's long-lived TLS identity.
pub struct AgentIdentity {
    /// DER-encoded self-signed certificate.
    pub cert_der: Vec<u8>,
    /// Lowercase hex SHA-256 of the certificate's SubjectPublicKeyInfo.
    pub fingerprint: String,
    /// PKCS#8 private key. Never exposed outside this crate.
    pub(crate) key_der: Vec<u8>,
}

impl fmt::Debug for AgentIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentIdentity")
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

/// Load `agent.key` and `agent.crt` from `dir`, or create them if neither exists.
///
/// If only one of the two files exists this is an error: regenerating would
/// change the fingerprint that desktops have pinned.
pub fn load_or_create_identity(dir: &Path) -> Result<AgentIdentity> {
    let key_path = dir.join(KEY_FILE);
    let cert_path = dir.join(CERT_FILE);
    match (key_path.exists(), cert_path.exists()) {
        (true, true) => {
            let key_der = fs::read(&key_path).with_context(|| format!("reading {key_path:?}"))?;
            let cert_der =
                fs::read(&cert_path).with_context(|| format!("reading {cert_path:?}"))?;
            let fingerprint = spki_fingerprint(&cert_der)
                .with_context(|| format!("{cert_path:?} is not a valid certificate"))?;
            let id = AgentIdentity {
                cert_der,
                fingerprint,
                key_der,
            };
            // Fail early if the key does not belong to the certificate.
            build_certified_key(&id).context("agent.key does not match agent.crt")?;
            Ok(id)
        }
        (false, false) => {
            create_dir_private(dir)?;
            let id = generate()?;
            write_atomic(dir, KEY_FILE, &id.key_der)?;
            write_atomic(dir, CERT_FILE, &id.cert_der)?;
            Ok(id)
        }
        (true, false) => bail!(
            "{key_path:?} exists but {cert_path:?} is missing. Restore the certificate, or remove both files to create a new identity (desktops will need to pair again)."
        ),
        (false, true) => bail!(
            "{cert_path:?} exists but {key_path:?} is missing. Restore the key, or remove both files to create a new identity (desktops will need to pair again)."
        ),
    }
}

fn generate() -> Result<AgentIdentity> {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "keel-agent");
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(VALIDITY_DAYS);
    let cert = params.self_signed(&key_pair)?;
    let cert_der = cert.der().to_vec();
    let fingerprint = spki_fingerprint(&cert_der)?;
    Ok(AgentIdentity {
        cert_der,
        fingerprint,
        key_der: key_pair.serialize_der(),
    })
}

fn create_dir_private(dir: &Path) -> Result<()> {
    if !dir.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("creating {dir:?}"))?;
    }
    Ok(())
}

/// Write `bytes` to `dir/name` via a temp file created with mode 0600, then rename.
fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let tmp = dir.join(format!(".{name}.tmp"));
    // A stale temp file from a crashed run is safe to discard.
    let _ = fs::remove_file(&tmp);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("creating {tmp:?}"))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, dir.join(name)).with_context(|| format!("installing {name}"))?;
    fs::File::open(dir)?.sync_all()?;
    Ok(())
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn build_certified_key(id: &AgentIdentity) -> Result<rustls::sign::CertifiedKey> {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(id.key_der.clone()));
    let signing_key = provider().key_provider.load_private_key(key)?;
    let ck = rustls::sign::CertifiedKey::new(
        vec![CertificateDer::from(id.cert_der.clone())],
        signing_key,
    );
    ck.keys_match()?;
    Ok(ck)
}

/// Client-certificate verifier for a world with no CA.
///
/// Trust is not established by a chain: any user presents their own
/// self-signed certificate, and authorization happens after the handshake by
/// looking up the certificate's public-key fingerprint ([`peer_fingerprint`]).
/// So this verifier
///
/// - requires a client certificate (`client_auth_mandatory` is true);
/// - accepts any well-formed end-entity certificate without chain, name or
///   expiry validation;
/// - still verifies the handshake signature (CertificateVerify) against the
///   presented certificate's key, so the client must actually hold the private
///   key whose fingerprint we will authorize;
/// - offers no root hint subjects, since there are no roots.
#[derive(Debug)]
struct AnySelfSignedClient {
    algs: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for AnySelfSignedClient {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        // Reject certificates we could not fingerprint later.
        spki_fingerprint(end_entity).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// TLS 1.3-only server config presenting the agent identity and requiring a
/// client certificate (see [`AnySelfSignedClient`]).
pub fn server_config(id: &AgentIdentity) -> Result<Arc<rustls::ServerConfig>> {
    let provider = provider();
    let verifier = Arc::new(AnySelfSignedClient {
        algs: provider.signature_verification_algorithms,
    });
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(id.key_der.clone()));
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![CertificateDer::from(id.cert_der.clone())], key)?;
    Ok(Arc::new(cfg))
}

/// SPKI fingerprint of the first certificate the peer presented, if any.
pub fn peer_fingerprint(conn: &rustls::ServerConnection) -> Option<String> {
    let cert = conn.peer_certificates()?.first()?;
    spki_fingerprint(cert).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn identity_created_then_reloaded_same_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let a = load_or_create_identity(dir.path()).unwrap();
        let b = load_or_create_identity(dir.path()).unwrap();
        assert_eq!(a.fingerprint, b.fingerprint);
        assert_eq!(a.cert_der, b.cert_der);
        assert_eq!(a.fingerprint.len(), 64);
        assert_eq!(
            keel_proto::spki_fingerprint(&a.cert_der).unwrap(),
            a.fingerprint
        );
    }

    #[test]
    fn key_file_mode_0600() {
        let dir = tempfile::tempdir().unwrap();
        load_or_create_identity(dir.path()).unwrap();
        let mode = std::fs::metadata(dir.path().join("agent.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn half_present_identity_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        load_or_create_identity(dir.path()).unwrap();
        std::fs::remove_file(dir.path().join("agent.crt")).unwrap();
        assert!(load_or_create_identity(dir.path()).is_err());
        assert!(
            !dir.path().join("agent.crt").exists(),
            "must not regenerate"
        );

        let dir = tempfile::tempdir().unwrap();
        load_or_create_identity(dir.path()).unwrap();
        std::fs::remove_file(dir.path().join("agent.key")).unwrap();
        assert!(load_or_create_identity(dir.path()).is_err());
        assert!(
            !dir.path().join("agent.key").exists(),
            "must not regenerate"
        );
    }

    #[test]
    fn mismatched_key_and_cert_is_an_error() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        load_or_create_identity(a.path()).unwrap();
        load_or_create_identity(b.path()).unwrap();
        std::fs::copy(b.path().join("agent.key"), a.path().join("agent.key")).unwrap();
        assert!(load_or_create_identity(a.path()).is_err());
    }

    fn client_config(cert: Option<(Vec<u8>, Vec<u8>)>) -> Arc<rustls::ClientConfig> {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let b = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServer));
        let cfg = match cert {
            Some((c, k)) => b
                .with_client_auth_cert(
                    vec![CertificateDer::from(c)],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(k)),
                )
                .unwrap(),
            None => b.with_no_client_auth(),
        };
        Arc::new(cfg)
    }

    #[derive(Debug)]
    struct AcceptAnyServer;
    impl rustls::client::danger::ServerCertVerifier for AcceptAnyServer {
        fn verify_server_cert(
            &self,
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &[rustls::pki_types::CertificateDer<'_>],
            _: &rustls::pki_types::ServerName<'_>,
            _: &[u8],
            _: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Err(rustls::Error::General("tls12 unsupported".into()))
        }
        fn verify_tls13_signature(
            &self,
            m: &[u8],
            c: &rustls::pki_types::CertificateDer<'_>,
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

    fn self_signed() -> (Vec<u8>, Vec<u8>) {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = rcgen::CertificateParams::new(vec![])
            .unwrap()
            .self_signed(&kp)
            .unwrap();
        (cert.der().to_vec(), kp.serialize_der())
    }

    #[tokio::test]
    async fn handshake_requires_client_key() {
        let dir = tempfile::tempdir().unwrap();
        let id = load_or_create_identity(dir.path()).unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config(&id).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let mut out = Vec::new();
            for _ in 0..2 {
                let (tcp, _) = listener.accept().await.unwrap();
                out.push(match acceptor.accept(tcp).await {
                    Ok(s) => Ok(peer_fingerprint(s.get_ref().1)),
                    Err(e) => Err(e.to_string()),
                });
            }
            out
        });

        let name = rustls::pki_types::ServerName::try_from("keel-agent").unwrap();

        // Client with a self-signed cert and its matching key succeeds.
        let (cert, key) = self_signed();
        let expected = keel_proto::spki_fingerprint(&cert).unwrap();
        let c = tokio_rustls::TlsConnector::from(client_config(Some((cert, key))));
        let tcp = TcpStream::connect(addr).await.unwrap();
        let _good = c.connect(name.clone(), tcp).await.unwrap();

        // Client without a certificate is rejected by the server.
        let c = tokio_rustls::TlsConnector::from(client_config(None));
        let tcp = TcpStream::connect(addr).await.unwrap();
        let _ = c.connect(name, tcp).await; // TLS 1.3 client may finish first

        let results = server.await.unwrap();
        assert_eq!(results[0], Ok(Some(expected)));
        assert!(
            results[1].is_err(),
            "no client cert must fail: {:?}",
            results[1]
        );
    }
}
