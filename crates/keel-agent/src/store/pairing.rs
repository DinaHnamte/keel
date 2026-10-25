use anyhow::Result;
use keel_proto::{Role, UserInfo};
use rusqlite::{OptionalExtension, TransactionBehavior};

use super::{Store, role_from_str, role_to_str};

#[derive(Debug, thiserror::Error)]
pub enum RedeemError {
    #[error("pairing token is unknown")]
    Unknown,
    #[error("pairing token was already used")]
    Used,
    #[error("pairing token has expired")]
    Expired,
    #[error("this key is already paired with the server")]
    AlreadyPaired,
    #[error("database error: {0}")]
    Db(String),
}

impl From<rusqlite::Error> for RedeemError {
    fn from(e: rusqlite::Error) -> Self {
        RedeemError::Db(e.to_string())
    }
}

impl Store {
    pub fn create_pairing_token(
        &self,
        token_hash: &[u8; 32],
        role: Role,
        expires_at: i64,
    ) -> Result<()> {
        self.lock().execute(
            "INSERT INTO pairing_tokens(token_hash, role, expires_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![&token_hash[..], role_to_str(role), expires_at],
        )?;
        Ok(())
    }

    /// Expire every unused token of `role` as of `now`. Used tokens are left
    /// as they are, so they keep reporting "used".
    pub fn expire_unused_pairing_tokens(&self, role: Role, now: i64) -> Result<()> {
        self.lock().execute(
            "UPDATE pairing_tokens SET expires_at = MIN(expires_at, ?1) \
             WHERE role = ?2 AND used_at IS NULL",
            rusqlite::params![now, role_to_str(role)],
        )?;
        Ok(())
    }

    pub fn redeem_pairing_token(
        &self,
        token_hash: &[u8; 32],
        fp: &str,
        display_name: &str,
        now: i64,
    ) -> Result<UserInfo, RedeemError> {
        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let tok: Option<(i64, String, i64, Option<i64>)> = tx
            .query_row(
                "SELECT id, role, expires_at, used_at FROM pairing_tokens WHERE token_hash = ?1",
                [&token_hash[..]],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let (token_id, role_s, expires_at, used_at) = tok.ok_or(RedeemError::Unknown)?;
        if used_at.is_some() {
            return Err(RedeemError::Used);
        }
        if expires_at <= now {
            return Err(RedeemError::Expired);
        }
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE key_fingerprint = ?1)",
            [fp],
            |r| r.get(0),
        )?;
        if exists {
            return Err(RedeemError::AlreadyPaired);
        }
        let role = role_from_str(&role_s).map_err(|e| RedeemError::Db(e.to_string()))?;
        tx.execute(
            "UPDATE pairing_tokens SET used_at = ?1 WHERE id = ?2",
            rusqlite::params![now, token_id],
        )?;
        tx.execute(
            "INSERT INTO users(display_name, key_fingerprint, role, created_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![display_name, fp, role_s, now],
        )?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(UserInfo {
            id,
            display_name: display_name.to_string(),
            role,
            key_fingerprint: fp.to_string(),
        })
    }
}
