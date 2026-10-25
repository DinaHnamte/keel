//! Request handlers. Pure request in, response out; the connection loop in
//! `server.rs` owns all I/O.

use std::net::IpAddr;
use std::path::Path;

use keel_proto::{ErrorCode, Permission, Principal, Request, Response, UserInfo, authorize};
use sha2::{Digest, Sha256};

use crate::store::{RedeemError, Store};
use crate::sysinfo::read_status;

pub const MSG_NOT_PAIRED: &str = "This device isn't paired with the server yet.";
pub const MSG_BAD_TOKEN: &str = "That pairing code isn't valid.";
pub const MSG_TOKEN_EXPIRED: &str = "That pairing code has expired. Create a new one.";
pub const MSG_UNSUPPORTED_PROTOCOL: &str = "This app and the server agent are on incompatible versions. Update both to the latest version.";
pub const MSG_MALFORMED: &str = "The request couldn't be understood.";
pub const MSG_ALREADY_PAIRED: &str = "This device is already paired with this server. Remove it from the app and add it again, or keep using it.";
pub const MSG_INTERNAL: &str = "Something went wrong on the server. Check the agent logs.";
pub const MSG_TOO_LARGE: &str = "That request was too large. Update the app and try again.";

const MAX_NAME_CHARS: usize = 64;

pub fn error(code: ErrorCode, message: &str) -> Response {
    Response::Error {
        code,
        message: message.to_string(),
    }
}

/// The request's wire name, used in audit actions.
pub fn request_name(req: &Request) -> &'static str {
    match req {
        Request::Hello { .. } => "Hello",
        Request::Pair { .. } => "Pair",
        Request::WhoAmI => "WhoAmI",
        Request::ServerStatus => "ServerStatus",
        Request::ListApps => "ListApps",
        Request::ListUsers => "ListUsers",
    }
}

fn audit(store: &Store, user_id: Option<i64>, action: &str, target: &str, peer: IpAddr) {
    if let Err(e) = store.audit(user_id, action, target, &peer.to_string()) {
        tracing::error!(error = %e, action, "could not write audit row");
    }
}

fn internal(what: &str, e: &dyn std::fmt::Display) -> Response {
    tracing::error!(error = %e, "{what}");
    error(ErrorCode::Internal, MSG_INTERNAL)
}

/// Handle one request.
///
/// `who` is the user and principal resolved from `fingerprint` for this very
/// request (`None` if the key is not paired). `data_dir` is only used for disk usage in
/// `ServerStatus`. Audit rows are written for pairing attempts and denials,
/// not for read-only requests.
pub fn handle(
    store: &Store,
    data_dir: &Path,
    who: Option<&(UserInfo, Principal)>,
    fingerprint: &str,
    req: Request,
    peer: IpAddr,
    now: i64,
) -> Response {
    match &req {
        // Hello is only valid as the first frame, which the connection handles.
        Request::Hello { .. } => return error(ErrorCode::Malformed, MSG_MALFORMED),
        Request::Pair {
            token,
            display_name,
        } => return pair(store, fingerprint, token, display_name, peer, now),
        _ => {}
    }
    let Some((user, who)) = who else {
        return error(ErrorCode::NotPaired, MSG_NOT_PAIRED);
    };
    // WhoAmI, ServerStatus and ListApps (filtered per app below) need only the
    // project-less ViewStatus, which every role has.
    let perm = match &req {
        Request::ListUsers => Permission::ManageUsers,
        _ => Permission::ViewStatus,
    };
    if let Err(denied) = authorize(who, perm, None) {
        let uid = Some(user.id);
        let name = request_name(&req);
        audit(store, uid, &format!("forbidden:{name}"), name, peer);
        return error(ErrorCode::Forbidden, &denied.to_string());
    }
    match req {
        Request::WhoAmI => Response::Me(user.clone()),
        Request::ServerStatus => match read_status(data_dir) {
            Ok(s) => Response::Status(s),
            Err(e) => internal("reading server status failed", &e),
        },
        Request::ListApps => match store.list_apps() {
            Ok(apps) => Response::Apps(
                apps.into_iter()
                    .filter(|a| authorize(who, Permission::ViewStatus, Some(a.project_id)).is_ok())
                    .collect(),
            ),
            Err(e) => internal("listing apps failed", &e),
        },
        Request::ListUsers => match store.list_users() {
            Ok(users) => Response::Users(users),
            Err(e) => internal("listing users failed", &e),
        },
        Request::Hello { .. } | Request::Pair { .. } => unreachable!("handled above"),
    }
}

fn pair(
    store: &Store,
    fingerprint: &str,
    token: &str,
    display_name: &str,
    peer: IpAddr,
    now: i64,
) -> Response {
    let fail = |reason: &str, code: ErrorCode, msg: &str| {
        audit(
            store,
            None,
            "pair_failed",
            &format!("{reason} fp={fingerprint}"),
            peer,
        );
        error(code, msg)
    };
    let name = display_name.trim();
    if name.is_empty()
        || name.chars().count() > MAX_NAME_CHARS
        || name.chars().any(char::is_control)
    {
        return fail("invalid_name", ErrorCode::Malformed, MSG_MALFORMED);
    }
    // The token is hashed exactly as the client sent it (see `init`).
    let hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    match store.redeem_pairing_token(&hash, fingerprint, name, now) {
        Ok(user) => {
            audit(
                store,
                Some(user.id),
                "pair",
                &format!("{} fp={fingerprint}", user.display_name),
                peer,
            );
            Response::Paired {
                user_id: user.id,
                role: user.role,
            }
        }
        Err(RedeemError::Unknown) => fail("unknown_token", ErrorCode::BadToken, MSG_BAD_TOKEN),
        Err(RedeemError::Used) => fail("used_token", ErrorCode::BadToken, MSG_BAD_TOKEN),
        Err(RedeemError::AlreadyPaired) => {
            fail("already_paired", ErrorCode::BadToken, MSG_ALREADY_PAIRED)
        }
        Err(RedeemError::Expired) => {
            fail("expired_token", ErrorCode::TokenExpired, MSG_TOKEN_EXPIRED)
        }
        Err(RedeemError::Db(e)) => {
            tracing::error!(error = %e, "pairing failed in the database");
            audit(store, None, "pair_failed", "internal", peer);
            error(ErrorCode::Internal, MSG_INTERNAL)
        }
    }
}
