//! Length-prefixed JSON framing: u32 big-endian length, then the JSON body.

use crate::messages::Request;
use serde::{Serialize, de::DeserializeOwned};
use std::{fmt, io};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_FRAME: usize = 1_048_576;

#[derive(Debug)]
pub enum FrameError {
    TooLarge,
    Malformed,
    Io(io::Error),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::TooLarge => write!(f, "message is too large"),
            FrameError::Malformed => write!(f, "message is malformed"),
            FrameError::Io(e) => write!(f, "connection error: {e}"),
        }
    }
}

impl std::error::Error for FrameError {}

pub async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(
    w: &mut W,
    msg: &T,
) -> io::Result<()> {
    let body = serde_json::to_vec(msg).map_err(io::Error::other)?;
    if body.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame too large",
        ));
    }
    let mut out = Vec::with_capacity(4 + body.len());
    // Safe: body.len() <= MAX_FRAME (1 MiB) was checked above, which fits in u32.
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    w.write_all(&out).await?;
    w.flush().await
}

pub async fn read_frame<R: AsyncRead + Unpin, T: DeserializeOwned>(
    r: &mut R,
) -> Result<T, FrameError> {
    let mut header = [0u8; 4];
    r.read_exact(&mut header).await.map_err(FrameError::Io)?;
    let len = u32::from_be_bytes(header) as usize;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge);
    }
    // Read incrementally so a lying header cannot force a large allocation.
    let mut body = Vec::new();
    r.take(len as u64)
        .read_to_end(&mut body)
        .await
        .map_err(FrameError::Io)?;
    if body.len() != len {
        return Err(FrameError::Malformed);
    }
    serde_json::from_slice(&body).map_err(|_| FrameError::Malformed)
}

/// Parse one complete frame (header plus body) from a byte slice.
pub fn decode_frame_bytes(buf: &[u8]) -> Result<Request, FrameError> {
    let (header, rest) = buf.split_first_chunk::<4>().ok_or(FrameError::Malformed)?;
    let len = u32::from_be_bytes(*header) as usize;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge);
    }
    if rest.len() != len {
        return Err(FrameError::Malformed);
    }
    serde_json::from_slice(rest).map_err(|_| FrameError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_requests() -> Vec<Request> {
        vec![
            Request::Hello {
                protocol: 1,
                client_version: "0.1.0".into(),
            },
            Request::Pair {
                token: "t".into(),
                display_name: "Dinah".into(),
            },
            Request::WhoAmI,
            Request::ServerStatus,
            Request::ListApps,
            Request::ListUsers,
        ]
    }

    #[tokio::test]
    async fn frame_roundtrip() {
        for req in all_requests() {
            let mut buf = Vec::new();
            write_frame(&mut buf, &req).await.unwrap();
            let got: Request = read_frame(&mut buf.as_slice()).await.unwrap();
            assert_eq!(got, req);
            assert_eq!(decode_frame_bytes(&buf).unwrap(), req);
        }
    }

    #[tokio::test]
    async fn every_response_variant_roundtrips() {
        use crate::messages::*;
        use crate::roles::{ProjectId, Role};
        let user = UserInfo {
            id: 2,
            display_name: "Dinah".into(),
            role: Role::Admin,
            key_fingerprint: "ab:cd".into(),
        };
        let app = AppSummary {
            id: 3,
            name: "web".into(),
            project_id: ProjectId(1),
            state: AppState::Live,
        };
        let status = ServerStatus {
            hostname: "h".into(),
            os_pretty_name: "Ubuntu 24.04".into(),
            arch: "x86_64".into(),
            uptime_secs: 10,
            load_1m: 0.5,
            mem_total_bytes: 100,
            mem_used_bytes: 50,
            disk_total_bytes: 200,
            disk_used_bytes: 100,
            agent_rss_bytes: 10,
        };
        let all = vec![
            Response::HelloOk {
                protocol: 1,
                agent_version: "0.1.0".into(),
                server_id: "s".into(),
            },
            Response::Paired {
                user_id: 1,
                role: Role::Owner,
            },
            Response::Me(user.clone()),
            Response::Status(status),
            Response::Apps(vec![]),
            Response::Apps(vec![app.clone(), app]),
            Response::Users(vec![]),
            Response::Users(vec![user.clone(), user]),
            Response::Error {
                code: ErrorCode::Forbidden,
                message: "no".into(),
            },
        ];
        for resp in all {
            let mut buf = Vec::new();
            write_frame(&mut buf, &resp).await.unwrap();
            let got: Response = read_frame(&mut buf.as_slice()).await.unwrap();
            assert_eq!(got, resp);
        }
    }

    #[tokio::test]
    async fn frame_rejects_oversize() {
        let header = ((MAX_FRAME + 1) as u32).to_be_bytes();
        // Only the header is available: a TooLarge result proves no body read.
        let r: Result<Request, _> = read_frame(&mut header.as_slice()).await;
        assert!(matches!(r, Err(FrameError::TooLarge)));
        assert!(matches!(
            decode_frame_bytes(&header),
            Err(FrameError::TooLarge)
        ));
    }

    #[tokio::test]
    async fn frame_accepts_exactly_max_header() {
        // A header of exactly MAX_FRAME is not TooLarge (body is just missing).
        let header = (MAX_FRAME as u32).to_be_bytes();
        let r: Result<Request, _> = read_frame(&mut header.as_slice()).await;
        assert!(matches!(r, Err(FrameError::Malformed)));
    }

    #[tokio::test]
    async fn frame_rejects_truncated() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &Request::WhoAmI).await.unwrap();
        buf.truncate(buf.len() - 1);
        let r: Result<Request, _> = read_frame(&mut buf.as_slice()).await;
        assert!(matches!(r, Err(FrameError::Malformed)));
        assert!(matches!(
            decode_frame_bytes(&buf),
            Err(FrameError::Malformed)
        ));
        assert!(matches!(
            decode_frame_bytes(&[0, 0]),
            Err(FrameError::Malformed)
        ));
    }

    #[tokio::test]
    async fn frame_rejects_bad_json() {
        let body = b"not json";
        let mut buf = (body.len() as u32).to_be_bytes().to_vec();
        buf.extend_from_slice(body);
        let r: Result<Request, _> = read_frame(&mut buf.as_slice()).await;
        assert!(matches!(r, Err(FrameError::Malformed)));
        assert!(matches!(
            decode_frame_bytes(&buf),
            Err(FrameError::Malformed)
        ));
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let body = br#"{"type":"WhoAmI"}"#;
        let mut buf = (body.len() as u32).to_be_bytes().to_vec();
        buf.extend_from_slice(body);
        buf.push(0);
        assert!(matches!(
            decode_frame_bytes(&buf),
            Err(FrameError::Malformed)
        ));
    }

    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[test]
    fn random_inputs_never_panic() {
        let mut s = 0x9E37_79B9_7F4A_7C15u64;
        for _ in 0..10_000 {
            let len = (xorshift(&mut s) % 64) as usize;
            let mut bytes: Vec<u8> = (0..len).map(|_| xorshift(&mut s) as u8).collect();
            // Sometimes make the header plausible so the JSON path is exercised.
            if len >= 4 && xorshift(&mut s).is_multiple_of(2) {
                bytes[..4].copy_from_slice(&((len - 4) as u32).to_be_bytes());
            }
            let _ = decode_frame_bytes(&bytes);
            let _ = crate::pairing::PairingCode::parse(&String::from_utf8_lossy(&bytes));
            let mut with_prefix = b"keel1:".to_vec();
            with_prefix.extend_from_slice(&bytes);
            let _ = crate::pairing::PairingCode::parse(&String::from_utf8_lossy(&with_prefix));
        }
    }
}
