//! Pairing codes: `keel1:` + base64url (no padding) of a JSON payload.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const PAIRING_PREFIX: &str = "keel1:";

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
        let rest = s
            .trim()
            .strip_prefix(PAIRING_PREFIX)
            .ok_or(PairingCodeError::WrongPrefix)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(rest)
            .map_err(|_| PairingCodeError::BadEncoding)?;
        serde_json::from_slice(&bytes).map_err(|_| PairingCodeError::BadPayload)
    }
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
