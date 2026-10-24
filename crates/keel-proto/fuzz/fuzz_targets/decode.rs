#![no_main]

use keel_proto::{PairingCode, decode_frame_bytes};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode_frame_bytes(data);
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = PairingCode::parse(s);
    }
});
