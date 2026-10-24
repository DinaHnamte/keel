//! Roles and permission checks (spec section 9).

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Owner,
    Admin,
    Developer,
    Viewer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    ViewStatus,
    ViewLogs,
    ReadSecrets,
    EditEnv,
    Deploy,
    Rollback,
    ManageProjects,
    ManageUsers,
    InviteOwner,
    ManageServer,
    UpgradeAgent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProjectId(pub i64);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    pub role: Role,
    pub projects: Vec<ProjectId>,
}

/// Returned when a role may not perform a permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Denied {
    pub perm: Permission,
}

impl fmt::Display for Denied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Your role can't do this.")
    }
}

impl std::error::Error for Denied {}

/// Check whether `p` may exercise `perm`, optionally on `project`.
pub fn authorize(
    p: &Principal,
    perm: Permission,
    project: Option<ProjectId>,
) -> Result<(), Denied> {
    use Permission::*;
    let denied = Err(Denied { perm });
    let member = |project: Option<ProjectId>| project.is_some_and(|id| p.projects.contains(&id));
    match p.role {
        Role::Owner => Ok(()),
        Role::Admin => match perm {
            InviteOwner | ManageServer | UpgradeAgent => denied,
            _ => Ok(()),
        },
        Role::Developer => match perm {
            ViewStatus if project.is_none() => Ok(()),
            ViewStatus | ViewLogs | ReadSecrets | EditEnv | Deploy | Rollback
                if member(project) =>
            {
                Ok(())
            }
            _ => denied,
        },
        Role::Viewer => match perm {
            ViewStatus if project.is_none() => Ok(()),
            ViewStatus | ViewLogs if member(project) => Ok(()),
            _ => denied,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_PERMS: [Permission; 11] = [
        Permission::ViewStatus,
        Permission::ViewLogs,
        Permission::ReadSecrets,
        Permission::EditEnv,
        Permission::Deploy,
        Permission::Rollback,
        Permission::ManageProjects,
        Permission::ManageUsers,
        Permission::InviteOwner,
        Permission::ManageServer,
        Permission::UpgradeAgent,
    ];

    fn expected(role: Role, perm: Permission, in_project: bool, scoped: bool) -> bool {
        use Permission::*;
        match role {
            Role::Owner => true,
            Role::Admin => !matches!(perm, InviteOwner | ManageServer | UpgradeAgent),
            Role::Developer => match perm {
                ViewStatus => !scoped || in_project,
                ViewLogs | ReadSecrets | EditEnv | Deploy | Rollback => scoped && in_project,
                _ => false,
            },
            Role::Viewer => match perm {
                ViewStatus => !scoped || in_project,
                ViewLogs => scoped && in_project,
                _ => false,
            },
        }
    }

    #[test]
    fn authorize_matrix() {
        let p1 = ProjectId(1);
        let p2 = ProjectId(2);
        for role in [Role::Owner, Role::Admin, Role::Developer, Role::Viewer] {
            let who = Principal {
                role,
                projects: vec![p1],
            };
            for perm in ALL_PERMS {
                for (project, scoped, in_project) in [
                    (None, false, false),
                    (Some(p1), true, true),
                    (Some(p2), true, false),
                ] {
                    let got = authorize(&who, perm, project).is_ok();
                    assert_eq!(
                        got,
                        expected(role, perm, in_project, scoped),
                        "{role:?} {perm:?} {project:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn developer_denied_on_other_project() {
        let dev = Principal {
            role: Role::Developer,
            projects: vec![ProjectId(1)],
        };
        let err = authorize(&dev, Permission::Deploy, Some(ProjectId(2))).unwrap_err();
        assert_eq!(err.perm, Permission::Deploy);
        assert_eq!(err.to_string(), "Your role can't do this.");
    }

    #[test]
    fn serde_names() {
        assert_eq!(serde_json::to_string(&Role::Owner).unwrap(), "\"owner\"");
        assert_eq!(
            serde_json::to_string(&Permission::ViewStatus).unwrap(),
            "\"view_status\""
        );
    }
}
