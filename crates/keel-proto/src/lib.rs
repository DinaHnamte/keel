pub mod codec;
pub mod messages;
pub mod pairing;
pub mod roles;
pub mod version;

pub use codec::{FrameError, MAX_FRAME, decode_frame_bytes, read_frame, write_frame};
pub use messages::{AppState, AppSummary, ErrorCode, Request, Response, ServerStatus, UserInfo};
pub use pairing::{PAIRING_PREFIX, PairingCode, PairingCodeError};
pub use roles::{Denied, Permission, Principal, ProjectId, Role, authorize};
pub use version::{MIN_PROTOCOL_VERSION, PROTOCOL_VERSION, negotiate};
