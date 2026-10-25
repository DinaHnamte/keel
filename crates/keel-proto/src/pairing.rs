//! Pairing codes: `keel1:` + base64url (no padding) of a JSON payload.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const PAIRING_PREFIX: &str = "keel1:";
/// Longest pairing code `parse` will look at.
const MAX_PAIRING_CODE_LEN: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingCode {
    pub host: String,
    pub port: u16,
    pub fingerprint: String,
    pub token: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingCodeError {
    WrongPrefix,
    BadEncoding,
    BadPayload,
}

impl fmt::Display for PairingCodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PairingCodeError::WrongPrefix => {
                write!(
                    f,
                    "This isn't a Keel pairing code. Copy the full code from the server and try again."
                )
            }
            PairingCodeError::BadEncoding | PairingCodeError::BadPayload => {
                write!(
                    f,
                    "The pairing code is damaged. Copy it again from the server."
                )
            }
        }
    }
}

impl std::error::Error for PairingCodeError {}

impl PairingCode {
    pub fn encode(&self) -> String {
        // Serializing plain strings and a u16 cannot fail.
        let json = serde_json::to_vec(self).expect("pairing code serializes");
        format!("{PAIRING_PREFIX}{}", URL_SAFE_NO_PAD.encode(json))
    }

    pub fn parse(s: &str) -> Result<PairingCode, PairingCodeError> {
        let s = s.trim();
        if s.len() > MAX_PAIRING_CODE_LEN {
            return Err(PairingCodeError::BadPayload);
        }
        let rest = s
            .strip_prefix(PAIRING_PREFIX)
            .ok_or(PairingCodeError::WrongPrefix)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(rest)
            .map_err(|_| PairingCodeError::BadEncoding)?;
        serde_json::from_slice(&bytes).map_err(|_| PairingCodeError::BadPayload)
    }
}

/// The certificate could not be parsed, so it has no fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FingerprintError;

impl fmt::Display for FingerprintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "The certificate is not valid DER-encoded X.509.")
    }
}

impl std::error::Error for FingerprintError {}

/// Lowercase hex SHA-256 of the certificate's DER-encoded SubjectPublicKeyInfo.
///
/// Identity in Keel is the public key, not the certificate: the same key
/// re-issued in a new certificate keeps the same fingerprint.
pub fn spki_fingerprint(cert_der: &[u8]) -> Result<String, FingerprintError> {
    use sha2::{Digest, Sha256};
    let (rest, cert) =
        x509_parser::parse_x509_certificate(cert_der).map_err(|_| FingerprintError)?;
    if !rest.is_empty() {
        return Err(FingerprintError);
    }
    Ok(hex::encode(Sha256::digest(
        cert.tbs_certificate.subject_pki.raw,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PairingCode {
        PairingCode {
            host: "203.0.113.7".into(),
            port: 7443,
            fingerprint: "sha256:abcd".into(),
            token: "tok-123".into(),
        }
    }

    #[test]
    fn pairing_code_roundtrip() {
        let c = sample();
        let s = c.encode();
        assert!(s.starts_with("keel1:"));
        assert!(!s.contains('=') && !s.contains('+') && !s.contains('/'));
        assert_eq!(PairingCode::parse(&s).unwrap(), c);
    }

    #[test]
    fn pairing_code_rejects_wrong_prefix() {
        let s = sample().encode().replacen("keel1:", "keel2:", 1);
        assert_eq!(PairingCode::parse(&s), Err(PairingCodeError::WrongPrefix));
    }

    #[test]
    fn pairing_code_trims_whitespace() {
        let s = format!("  {}\r\n", sample().encode());
        assert_eq!(PairingCode::parse(&s).unwrap(), sample());
    }

    #[test]
    fn pairing_code_rejects_oversize() {
        let s = format!("keel1:{}", "A".repeat(5000));
        assert_eq!(PairingCode::parse(&s), Err(PairingCodeError::BadPayload));
    }

    #[test]
    fn pairing_code_rejects_garbage() {
        assert_eq!(
            PairingCode::parse("keel1:!!!"),
            Err(PairingCodeError::BadEncoding)
        );
        assert_eq!(
            PairingCode::parse("keel1:e30"),
            Err(PairingCodeError::BadPayload)
        );
    }
}
