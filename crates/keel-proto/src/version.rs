//! Protocol versioning.

use crate::messages::ErrorCode;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MIN_PROTOCOL_VERSION: u16 = 1;

/// Pick the protocol version to speak with a client that offers `client`.
pub fn negotiate(client: u16) -> Result<u16, ErrorCode> {
    if (MIN_PROTOCOL_VERSION..=PROTOCOL_VERSION).contains(&client) {
        Ok(client)
    } else {
        Err(ErrorCode::UnsupportedProtocol)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiate_accepts_current_and_rejects_newer() {
        assert_eq!(negotiate(1), Ok(1));
        assert_eq!(negotiate(2), Err(ErrorCode::UnsupportedProtocol));
        assert_eq!(negotiate(0), Err(ErrorCode::UnsupportedProtocol));
    }
}
