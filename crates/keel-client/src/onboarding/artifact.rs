//! Agent binaries are only installed if they carry a valid Ed25519 signature.

use anyhow::{Result, bail};
use ring::signature::{ED25519, UnparsedPublicKey};

/// The public key agent binaries are signed with, embedded at build time
/// (see `build.rs`).
pub const RELEASE_PUBKEY: [u8; 32] = include!(concat!(env!("OUT_DIR"), "/release_pubkey.rs"));

/// Check `sig` is a valid Ed25519 signature over `bin` by `pubkey`.
pub fn verify_agent_artifact(bin: &[u8], sig: &[u8; 64], pubkey: &[u8; 32]) -> Result<()> {
    let key = UnparsedPublicKey::new(&ED25519, pubkey);
    if key.verify(bin, sig).is_err() {
        bail!(
            "The agent program bundled with this app failed its signature check, so it wasn't installed. Reinstall Keel from the official download."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn keypair(seed: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
    }

    fn sign(kp: &Ed25519KeyPair, bin: &[u8]) -> [u8; 64] {
        kp.sign(bin).as_ref().try_into().unwrap()
    }

    fn public(kp: &Ed25519KeyPair) -> [u8; 32] {
        kp.public_key().as_ref().try_into().unwrap()
    }

    #[test]
    fn artifact_signature_valid() {
        let kp = keypair(7);
        let bin = b"\x7fELF pretend agent binary".to_vec();
        verify_agent_artifact(&bin, &sign(&kp, &bin), &public(&kp)).unwrap();
    }

    #[test]
    fn artifact_signature_tampered_rejected() {
        let kp = keypair(7);
        let bin = b"\x7fELF pretend agent binary".to_vec();
        let sig = sign(&kp, &bin);

        let mut tampered = bin.clone();
        tampered[5] ^= 1;
        let err = verify_agent_artifact(&tampered, &sig, &public(&kp)).unwrap_err();
        assert!(err.to_string().contains("signature"), "{err}");

        let mut bad_sig = sig;
        bad_sig[0] ^= 1;
        assert!(verify_agent_artifact(&bin, &bad_sig, &public(&kp)).is_err());

        let other = keypair(8);
        assert!(verify_agent_artifact(&bin, &sig, &public(&other)).is_err());
    }

    #[test]
    fn debug_build_embeds_dev_key() {
        if std::env::var("KEEL_RELEASE_PUBKEY").is_ok() || !cfg!(debug_assertions) {
            return;
        }
        let text = include_str!("../../dev-release.pub");
        let hex: String = text.lines().filter(|l| !l.starts_with('#')).collect();
        assert_eq!(hex::encode(RELEASE_PUBKEY), hex.trim());
    }

    #[test]
    fn dev_key_file_matches_dev_pubkey() {
        let key = include_str!("../../dev-release.key");
        assert!(key.starts_with("# DEV ONLY"));
        let seed = hex::decode(key.lines().nth(1).unwrap().trim()).unwrap();
        let kp = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        let pubtext = include_str!("../../dev-release.pub");
        let hex: String = pubtext.lines().filter(|l| !l.starts_with('#')).collect();
        assert_eq!(hex::encode(kp.public_key().as_ref()), hex.trim());
    }
}
