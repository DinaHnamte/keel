//! The list of known servers, stored as `servers.json`.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerRecord {
    /// The agent's server_id.
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    /// Pinned agent public-key fingerprint.
    pub fingerprint: String,
    pub ssh_saved: bool,
}

pub struct ServerStore {
    path: PathBuf,
    records: Vec<ServerRecord>,
}

impl ServerStore {
    /// Load `servers.json` from `dir`. Creates nothing until the first write.
    pub fn load(dir: &Path) -> io::Result<ServerStore> {
        let path = dir.join("servers.json");
        let records = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e),
        };
        Ok(ServerStore { path, records })
    }

    pub fn list(&self) -> &[ServerRecord] {
        &self.records
    }

    /// Add a record, or replace the one with the same `id`.
    pub fn upsert(&mut self, rec: ServerRecord) -> io::Result<()> {
        let mut next = self.records.clone();
        match next.iter_mut().find(|r| r.id == rec.id) {
            Some(slot) => *slot = rec,
            None => next.push(rec),
        }
        self.write(&next)?;
        self.records = next;
        Ok(())
    }

    pub fn remove(&mut self, id: &str) -> io::Result<()> {
        let next: Vec<_> = self
            .records
            .iter()
            .filter(|r| r.id != id)
            .cloned()
            .collect();
        if next.len() == self.records.len() {
            return Ok(());
        }
        self.write(&next)?;
        self.records = next;
        Ok(())
    }

    /// Temp file in the same directory, fsync, then rename over the target.
    fn write(&self, records: &[ServerRecord]) -> io::Result<()> {
        let dir = self.path.parent().unwrap_or(Path::new("."));
        fs::create_dir_all(dir)?;
        let tmp = dir.join(".servers.json.tmp");
        let json = serde_json::to_vec_pretty(records).map_err(io::Error::other)?;
        {
            let mut f = File::create(&tmp)?;
            f.write_all(&json)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        #[cfg(unix)]
        File::open(dir)?.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, name: &str) -> ServerRecord {
        ServerRecord {
            id: id.into(),
            name: name.into(),
            host: "h".into(),
            port: 7443,
            fingerprint: "ab:cd".into(),
            ssh_saved: false,
        }
    }

    #[test]
    fn server_store_atomic_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = ServerStore::load(dir.path()).unwrap();
        assert!(s.list().is_empty());
        assert!(
            !dir.path().join("servers.json").exists(),
            "nothing created before a write"
        );
        s.upsert(rec("a", "one")).unwrap();
        s.upsert(rec("b", "two")).unwrap();
        s.upsert(rec("a", "renamed")).unwrap();
        let s2 = ServerStore::load(dir.path()).unwrap();
        assert_eq!(s2.list(), &[rec("a", "renamed"), rec("b", "two")]);
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(leftovers, vec![std::ffi::OsString::from("servers.json")]);
        let mut s2 = s2;
        s2.remove("a").unwrap();
        assert_eq!(
            ServerStore::load(dir.path()).unwrap().list(),
            &[rec("b", "two")]
        );
    }

    #[test]
    fn corrupt_file_is_an_error_not_silently_empty() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("servers.json"), b"{nope").unwrap();
        assert!(ServerStore::load(dir.path()).is_err());
    }
}
