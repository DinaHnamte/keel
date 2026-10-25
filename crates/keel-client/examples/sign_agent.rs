//! Sign an agent binary with an Ed25519 key.
//!
//! cargo run -p keel-client --example sign_agent -- <key-hex-file> <binary> <out.sig>
//!
//! The key file holds the 32-byte seed as hex; lines starting with `#` are
//! ignored. The signature is written as 64 raw bytes.

use std::process::ExitCode;

use ring::signature::{Ed25519KeyPair, KeyPair};

fn run(key_path: &str, bin_path: &str, out_path: &str) -> Result<String, String> {
    let text = std::fs::read_to_string(key_path).map_err(|e| format!("reading {key_path}: {e}"))?;
    let hex: String = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    let seed = hex::decode(&hex).map_err(|_| format!("{key_path} is not valid hex"))?;
    let kp = Ed25519KeyPair::from_seed_unchecked(&seed)
        .map_err(|_| format!("{key_path} must hold a 32-byte Ed25519 seed"))?;
    let bin = std::fs::read(bin_path).map_err(|e| format!("reading {bin_path}: {e}"))?;
    std::fs::write(out_path, kp.sign(&bin).as_ref())
        .map_err(|e| format!("writing {out_path}: {e}"))?;
    Ok(hex::encode(kp.public_key().as_ref()))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [key, bin, out] = args.as_slice() else {
        eprintln!("usage: sign_agent <key-hex-file> <binary> <out.sig>");
        return ExitCode::from(2);
    };
    match run(key, bin, out) {
        Ok(public) => {
            println!("signed {bin} -> {out} (public key {public})");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
