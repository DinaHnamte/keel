use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::{Context, Result};
use keel_proto::{AppState, Role};
use rusqlite::Connection;

mod audit;
mod pairing;
mod users;

pub use pairing::RedeemError;

const SCHEMA_V1: &str = "
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    display_name TEXT NOT NULL,
    key_fingerprint TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE projects (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE);
CREATE TABLE project_members (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, project_id)
);
CREATE TABLE apps (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    project_id INTEGER NOT NULL REFERENCES projects(id),
    state TEXT NOT NULL
);
CREATE TABLE pairing_tokens (
    id INTEGER PRIMARY KEY,
    token_hash BLOB NOT NULL UNIQUE,
    role TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER
);
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY,
    at INTEGER NOT NULL,
    user_id INTEGER,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    device TEXT NOT NULL
);
";

/// Ordered migrations; migration N brings `user_version` to N.
const MIGRATIONS: &[&str] = &[SCHEMA_V1];

#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
}

pub(crate) fn role_to_str(r: Role) -> &'static str {
    match r {
        Role::Owner => "owner",
        Role::Admin => "admin",
        Role::Developer => "developer",
        Role::Viewer => "viewer",
    }
}

pub(crate) fn role_from_str(s: &str) -> Result<Role> {
    Ok(match s {
        "owner" => Role::Owner,
        "admin" => Role::Admin,
        "developer" => Role::Developer,
        "viewer" => Role::Viewer,
        other => anyhow::bail!("unknown role in database: {other}"),
    })
}

pub(crate) fn state_from_str(s: &str) -> Result<AppState> {
    Ok(match s {
        "live" => AppState::Live,
        "building" => AppState::Building,
        "degraded" => AppState::Degraded,
        "down" => AppState::Down,
        other => anyhow::bail!("unknown app state in database: {other}"),
    })
}

impl Store {
    /// Open (creating if needed) a file database with WAL and foreign keys on.
    pub fn open(path: &Path) -> Result<Store> {
        let conn = Connection::open(path)
            .with_context(|| format!("opening database {}", path.display()))?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        Self::init(conn)
    }

    /// In-memory database (WAL does not apply to it).
    pub fn open_in_memory() -> Result<Store> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(mut conn: Connection) -> Result<Store> {
        conn.pragma_update(None, "foreign_keys", true)?;
        migrate(&mut conn)?;
        Ok(Store {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The stable random id of this server, created on first use.
    pub fn server_id(&self) -> Result<String> {
        let conn = self.lock();
        let new_id = uuid::Uuid::new_v4().to_string();
        conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES ('server_id', ?1)",
            [&new_id],
        )?;
        Ok(
            conn.query_row("SELECT value FROM meta WHERE key = 'server_id'", [], |r| {
                r.get(0)
            })?,
        )
    }
}

fn migrate(conn: &mut Connection) -> Result<()> {
    let current: usize = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    for (i, sql) in MIGRATIONS.iter().enumerate().skip(current) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.pragma_update(None, "user_version", i + 1)?;
        tx.commit()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_db() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("keel-store-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d.join("keel.db")
    }

    fn user_version(s: &Store) -> i64 {
        s.lock()
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn migrations_idempotent() {
        let p = tmp_db();
        let a = Store::open(&p).unwrap();
        let id = a.server_id().unwrap();
        assert_eq!(user_version(&a), 1);
        drop(a);
        let b = Store::open(&p).unwrap();
        assert_eq!(user_version(&b), 1);
        assert_eq!(b.server_id().unwrap(), id);
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    #[test]
    fn server_id_stable() {
        let s = Store::open_in_memory().unwrap();
        let a = s.server_id().unwrap();
        assert_eq!(a, s.server_id().unwrap());
        assert_eq!(a.len(), 36);
        assert_ne!(a, Store::open_in_memory().unwrap().server_id().unwrap());
    }

    #[test]
    fn redeem_happy_path() {
        let s = Store::open_in_memory().unwrap();
        s.create_pairing_token(&[1; 32], Role::Owner, 1000).unwrap();
        let u = s
            .redeem_pairing_token(&[1; 32], "fp1", "Dinah", 500)
            .unwrap();
        assert_eq!(u.role, Role::Owner);
        assert_eq!(u.display_name, "Dinah");
        assert_eq!(u.key_fingerprint, "fp1");
        let (found, projects) = s.find_user_by_fingerprint("fp1").unwrap().unwrap();
        assert_eq!(found, u);
        assert!(projects.is_empty());
        assert_eq!(s.list_users().unwrap(), vec![u]);
        assert!(s.find_user_by_fingerprint("nope").unwrap().is_none());
    }

    #[test]
    fn redeem_unknown_fails() {
        let s = Store::open_in_memory().unwrap();
        let e = s.redeem_pairing_token(&[9; 32], "fp", "x", 0).unwrap_err();
        assert!(matches!(e, RedeemError::Unknown));
    }

    #[test]
    fn redeem_twice_fails_used() {
        let s = Store::open_in_memory().unwrap();
        s.create_pairing_token(&[1; 32], Role::Admin, 1000).unwrap();
        s.redeem_pairing_token(&[1; 32], "fp1", "A", 10).unwrap();
        let e = s
            .redeem_pairing_token(&[1; 32], "fp2", "B", 20)
            .unwrap_err();
        assert!(matches!(e, RedeemError::Used));
    }

    #[test]
    fn redeem_expired_fails() {
        let s = Store::open_in_memory().unwrap();
        s.create_pairing_token(&[1; 32], Role::Admin, 100).unwrap();
        let e = s
            .redeem_pairing_token(&[1; 32], "fp1", "A", 100)
            .unwrap_err();
        assert!(matches!(e, RedeemError::Expired));
        assert!(s.list_users().unwrap().is_empty());
    }

    #[test]
    fn redeem_same_fingerprint_twice_already_paired() {
        let s = Store::open_in_memory().unwrap();
        s.create_pairing_token(&[1; 32], Role::Owner, 1000).unwrap();
        s.create_pairing_token(&[2; 32], Role::Viewer, 1000)
            .unwrap();
        s.redeem_pairing_token(&[1; 32], "fp1", "A", 10).unwrap();
        let e = s
            .redeem_pairing_token(&[2; 32], "fp1", "A2", 10)
            .unwrap_err();
        assert!(matches!(e, RedeemError::AlreadyPaired));
        // the second token was not consumed: a different key can still use it
        let u = s.redeem_pairing_token(&[2; 32], "fp2", "B", 11).unwrap();
        assert_eq!(u.role, Role::Viewer);
    }

    #[test]
    fn audit_row_written() {
        let s = Store::open_in_memory().unwrap();
        s.audit(None, "pair", "user:1", "laptop").unwrap();
        let (n, action, user): (i64, String, Option<i64>) = s
            .lock()
            .query_row("SELECT count(*), action, user_id FROM audit_log", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
        assert_eq!((n, action.as_str(), user), (1, "pair", None));
    }

    #[test]
    fn apps_listed_by_name_and_members_returned() {
        let s = Store::open_in_memory().unwrap();
        {
            let c = s.lock();
            c.execute("INSERT INTO projects(id,name) VALUES (1,'p')", [])
                .unwrap();
            c.execute("INSERT INTO apps(name,project_id,state) VALUES ('zeta',1,'live'),('alpha',1,'building')", []).unwrap();
        }
        let apps = s.list_apps().unwrap();
        assert_eq!(apps[0].name, "alpha");
        assert_eq!(apps[0].state, keel_proto::AppState::Building);
        assert_eq!(apps[1].name, "zeta");
        s.create_pairing_token(&[1; 32], Role::Developer, 1000)
            .unwrap();
        let u = s.redeem_pairing_token(&[1; 32], "fp", "D", 1).unwrap();
        s.lock()
            .execute("INSERT INTO project_members VALUES (?1, 1)", [u.id])
            .unwrap();
        let (_, ps) = s.find_user_by_fingerprint("fp").unwrap().unwrap();
        assert_eq!(ps, vec![keel_proto::ProjectId(1)]);
    }

    #[test]
    fn concurrent_redeem_single_use() {
        let p = tmp_db();
        let s = Store::open(&p).unwrap();
        s.create_pairing_token(&[7; 32], Role::Owner, 1000).unwrap();
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let s = s.clone();
                std::thread::spawn(move || {
                    s.redeem_pairing_token(&[7; 32], &format!("fp{i}"), "U", 10)
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert!(
            results
                .iter()
                .filter_map(|r| r.as_ref().err())
                .all(|e| matches!(e, RedeemError::Used))
        );
        assert_eq!(s.list_users().unwrap().len(), 1);
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }
}
