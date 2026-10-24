//! Desktop client core: device identity, known servers, pinned mTLS connection.

pub mod connection;
pub mod identity;
pub mod onboarding;
pub mod servers;

pub use connection::{ConnectError, Connection, HelloInfo, pair};
#[cfg(feature = "os-keychain")]
pub use identity::OsKeychain;
pub use identity::{DeviceIdentity, Keychain, MemoryKeychain};
pub use servers::{ServerRecord, ServerStore};
