//! Embeds the Ed25519 public key that agent binaries must be signed with.
//!
//! Release builds take it from `KEEL_RELEASE_PUBKEY` (64 hex characters) and
//! refuse to build without it, so the committed dev key can never end up
//! trusted by a shipped app. Debug builds fall back to `dev-release.pub`.

use std::env;
use std::fs;
use std::path::PathBuf;

fn parse_hex_key(text: &str, source: &str) -> [u8; 32] {
    let hex: String = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    if hex.len() != 64 {
        panic!(
            "{source} must be 64 hex characters (an Ed25519 public key), got {} characters",
            hex.len()
        );
    }
    let mut key = [0u8; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .unwrap_or_else(|_| panic!("{source} is not valid hex"));
    }
    key
}

fn main() {
    println!("cargo:rerun-if-env-changed=KEEL_RELEASE_PUBKEY");
    println!("cargo:rerun-if-changed=dev-release.pub");

    let profile = env::var("PROFILE").unwrap_or_default();
    let key = match env::var("KEEL_RELEASE_PUBKEY") {
        Ok(v) if !v.trim().is_empty() => {
            let key = parse_hex_key(&v, "KEEL_RELEASE_PUBKEY");
            if profile == "release" {
                let dev = fs::read_to_string("dev-release.pub")
                    .map(|t| parse_hex_key(&t, "dev-release.pub"))
                    .ok();
                if dev == Some(key) {
                    panic!(
                        "KEEL_RELEASE_PUBKEY is the committed dev key. Release builds must use the real release signing key."
                    );
                }
            }
            key
        }
        _ if profile == "release" => panic!(
            "KEEL_RELEASE_PUBKEY is not set. Release builds must embed the release signing \
             public key (64 hex characters); the committed dev key is only for debug builds."
        ),
        _ => {
            let text = fs::read_to_string("dev-release.pub")
                .expect("dev-release.pub is missing from crates/keel-client");
            parse_hex_key(&text, "dev-release.pub")
        }
    };

    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is set by cargo"));
    fs::write(out.join("release_pubkey.rs"), format!("{key:?}"))
        .expect("could not write release_pubkey.rs");
}
