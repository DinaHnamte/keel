//! `keel-agent init`: prepare the data directory, TLS identity and database,
//! and issue a one-time Owner pairing code.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use keel_proto::{PairingCode, Role};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::config::AgentConfig;
use crate::store::Store;
use crate::tls::load_or_create_identity;

/// How long a freshly issued pairing token stays valid.
const TOKEN_TTL_SECS: i64 = 86_400;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitOutput {
    pub fingerprint: String,
    pub pairing_code: PairingCode,
}

fn ensure_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .with_context(|| format!("could not create {}", path.display()))?;
    }
    Ok(())
}

/// Set up the agent and issue an Owner pairing code. Safe to re-run.
///
/// Creates `cfg.data_dir` (mode 0700) if missing, opens or creates
/// `<data_dir>/keel.db`, loads or creates the TLS identity in
/// `<data_dir>/tls/` (so the fingerprint never changes on re-run), and adds a
/// new Owner pairing token that expires `now + 86_400`. Earlier unused Owner
/// tokens are expired so only the newest code works; used ones stay used.
///
/// The token is 32 bytes from the OS random source, encoded base64url without
/// padding. Only `SHA-256(encoded token string as UTF-8 bytes)` is stored.
/// Redemption (Task 6) must hash the token string the client sends, exactly as
/// received, in the same way.
pub fn init(cfg: &AgentConfig, host: &str, now: i64) -> Result<InitOutput> {
    ensure_dir(&cfg.data_dir)?;
    let tls_dir = cfg.data_dir.join("tls");
    ensure_dir(&tls_dir)?;
    // A pre-existing data dir may be too open; the key material lives below it.
    let _ = fs::set_permissions(&cfg.data_dir, fs::Permissions::from_mode(0o700));

    let identity =
        load_or_create_identity(&tls_dir).context("could not set up the TLS identity")?;
    let db_path = cfg.data_dir.join("keel.db");
    let store = Store::open(&db_path)?;

    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let token = URL_SAFE_NO_PAD.encode(raw);
    let hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    store
        .expire_unused_pairing_tokens(Role::Owner, now)
        .context("could not retire the previous pairing code")?;
    store
        .create_pairing_token(&hash, Role::Owner, now + TOKEN_TTL_SECS)
        .context("could not save the pairing token")?;

    Ok(InitOutput {
        fingerprint: identity.fingerprint.clone(),
        pairing_code: PairingCode {
            host: host.to_string(),
            port: cfg.listen.port(),
            fingerprint: identity.fingerprint,
            token,
        },
    })
}
