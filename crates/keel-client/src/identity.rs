//! The device's identity: an ECDSA P-256 key pair kept in the OS keychain.

use std::collections::HashMap;
use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use keel_proto::spki_fingerprint;
use serde::{Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Secret storage. Values are opaque bytes.
pub trait Keychain: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    fn set(&self, key: &str, value: &[u8]) -> Result<()>;
    fn delete(&self, key: &str) -> Result<()>;
}

/// In-memory keychain for tests.
#[derive(Default)]
pub struct MemoryKeychain {
    items: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemoryKeychain {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Keychain for MemoryKeychain {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.items.lock().unwrap().get(key).cloned())
    }
    fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        self.items
            .lock()
            .unwrap()
            .insert(key.to_string(), value.to_vec());
        Ok(())
    }
    fn delete(&self, key: &str) -> Result<()> {
        self.items.lock().unwrap().remove(key);
        Ok(())
    }
}

/// The operating system's keychain (service `keel`).
#[cfg(feature = "os-keychain")]
pub struct OsKeychain;

#[cfg(feature = "os-keychain")]
impl OsKeychain {
    fn entry(key: &str) -> Result<keyring::Entry> {
        Ok(keyring::Entry::new("keel", key)?)
    }
}

#[cfg(feature = "os-keychain")]
impl Keychain for OsKeychain {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        match Self::entry(key)?.get_secret() {
            Ok(v) => Ok(Some(v)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        Ok(Self::entry(key)?.set_secret(value)?)
    }
    fn delete(&self, key: &str) -> Result<()> {
        match Self::entry(key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

const IDENTITY_KEY: &str = "device-identity";

#[derive(Serialize, Deserialize)]
struct Stored {
    cert_der_b64: String,
    key_der_b64: String,
}

#[derive(Clone)]
pub struct DeviceIdentity {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub fingerprint: String,
}

impl std::fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

impl DeviceIdentity {
    /// Load the identity from the keychain, creating and storing one if absent.
    pub fn load_or_create(kc: &dyn Keychain) -> Result<DeviceIdentity> {
        if let Some(bytes) = kc.get(IDENTITY_KEY)? {
            let s: Stored = serde_json::from_slice(&bytes)?;
            let cert_der = STANDARD.decode(s.cert_der_b64)?;
            let key_der = STANDARD.decode(s.key_der_b64)?;
            let fingerprint = spki_fingerprint(&cert_der)?;
            return Ok(DeviceIdentity {
                cert_der,
                key_der,
                fingerprint,
            });
        }
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let cert = rcgen::CertificateParams::new(vec![])?.self_signed(&kp)?;
        let cert_der = cert.der().to_vec();
        let key_der = kp.serialize_der();
        let fingerprint = spki_fingerprint(&cert_der)?;
        let stored = Stored {
            cert_der_b64: STANDARD.encode(&cert_der),
            key_der_b64: STANDARD.encode(&key_der),
        };
        kc.set(IDENTITY_KEY, &serde_json::to_vec(&stored)?)?;
        Ok(DeviceIdentity {
            cert_der,
            key_der,
            fingerprint,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_persists_in_keychain() {
        let kc = MemoryKeychain::new();
        let a = DeviceIdentity::load_or_create(&kc).unwrap();
        let b = DeviceIdentity::load_or_create(&kc).unwrap();
        assert_eq!(a.fingerprint, b.fingerprint);
        assert_eq!(a.key_der, b.key_der);
        assert!(!a.fingerprint.is_empty());
    }

    #[test]
    fn separate_keychains_get_distinct_identities() {
        let a = DeviceIdentity::load_or_create(&MemoryKeychain::new()).unwrap();
        let b = DeviceIdentity::load_or_create(&MemoryKeychain::new()).unwrap();
        assert_ne!(a.fingerprint, b.fingerprint);
    }
}
