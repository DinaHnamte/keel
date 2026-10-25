use anyhow::Result;
use keel_proto::{AppSummary, ProjectId, UserInfo};

use super::{Store, role_from_str, state_from_str};

fn row_to_user(r: &rusqlite::Row<'_>) -> rusqlite::Result<(i64, String, String, String)> {
    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
}

fn build_user(
    (id, display_name, key_fingerprint, role): (i64, String, String, String),
) -> Result<UserInfo> {
    Ok(UserInfo {
        id,
        display_name,
        role: role_from_str(&role)?,
        key_fingerprint,
    })
}

impl Store {
    pub fn find_user_by_fingerprint(&self, fp: &str) -> Result<Option<(UserInfo, Vec<ProjectId>)>> {
        let conn = self.lock();
        let row = match conn.query_row(
            "SELECT id, display_name, key_fingerprint, role FROM users WHERE key_fingerprint = ?1",
            [fp],
            row_to_user,
        ) {
            Ok(r) => r,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let user = build_user(row)?;
        let mut stmt = conn.prepare(
            "SELECT project_id FROM project_members WHERE user_id = ?1 ORDER BY project_id",
        )?;
        let projects = stmt
            .query_map([user.id], |r| r.get::<_, i64>(0).map(ProjectId))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Some((user, projects)))
    }

    pub fn list_users(&self) -> Result<Vec<UserInfo>> {
        let conn = self.lock();
        let mut stmt =
            conn.prepare("SELECT id, display_name, key_fingerprint, role FROM users ORDER BY id")?;
        let rows = stmt
            .query_map([], row_to_user)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter().map(build_user).collect()
    }

    /// All apps, ordered by name. Permission filtering is the caller's job.
    pub fn list_apps(&self) -> Result<Vec<AppSummary>> {
        let conn = self.lock();
        let mut stmt =
            conn.prepare("SELECT id, name, project_id, state FROM apps ORDER BY name")?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(|(id, name, pid, state)| {
                Ok(AppSummary {
                    id,
                    name,
                    project_id: ProjectId(pid),
                    state: state_from_str(&state)?,
                })
            })
            .collect()
    }
}
