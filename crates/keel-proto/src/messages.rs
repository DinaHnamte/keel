//! Request and response messages.

use crate::roles::{ProjectId, Role};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Request {
    Hello {
        protocol: u16,
        client_version: String,
    },
    Pair {
        token: String,
        display_name: String,
    },
    WhoAmI,
    ServerStatus,
    ListApps,
    ListUsers,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Response {
    HelloOk {
        protocol: u16,
        agent_version: String,
        server_id: String,
    },
    Paired {
        user_id: i64,
        role: Role,
    },
    Me(UserInfo),
    Status(ServerStatus),
    Apps(Vec<AppSummary>),
    Users(Vec<UserInfo>),
    Error {
        code: ErrorCode,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerStatus {
    pub hostname: String,
    pub os_pretty_name: String,
    pub arch: String,
    pub uptime_secs: u64,
    pub load_1m: f32,
    pub mem_total_bytes: u64,
    pub mem_used_bytes: u64,
    pub disk_total_bytes: u64,
    pub disk_used_bytes: u64,
    pub agent_rss_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSummary {
    pub id: i64,
    pub name: String,
    pub project_id: ProjectId,
    pub state: AppState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppState {
    Live,
    Building,
    Degraded,
    Down,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: i64,
    pub display_name: String,
    pub role: Role,
    pub key_fingerprint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    UnsupportedProtocol,
    NotPaired,
    Forbidden,
    BadToken,
    TokenExpired,
    TooLarge,
    Malformed,
    Internal,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_roundtrip_json() {
        let r = Response::Me(UserInfo {
            id: 1,
            display_name: "Dinah".into(),
            role: Role::Owner,
            key_fingerprint: "ab:cd".into(),
        });
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<Response>(&s).unwrap(), r);
        let e = Response::Error {
            code: ErrorCode::Forbidden,
            message: "no".into(),
        };
        let s = serde_json::to_string(&e).unwrap();
        assert!(s.contains("\"type\":\"Error\""));
        assert_eq!(serde_json::from_str::<Response>(&s).unwrap(), e);
    }
}
