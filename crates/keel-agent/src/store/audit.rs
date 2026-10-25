use anyhow::Result;

use super::Store;

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl Store {
    pub fn audit(
        &self,
        user_id: Option<i64>,
        action: &str,
        target: &str,
        device: &str,
    ) -> Result<()> {
        self.lock().execute(
            "INSERT INTO audit_log(at, user_id, action, target, device) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![now_secs(), user_id, action, target, device],
        )?;
        Ok(())
    }
}
