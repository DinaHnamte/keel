//! Server status from `/proc`, `/etc/os-release` and `statvfs`.
//!
//! The parsers are pure functions over `&str` so they test on any OS.

use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use keel_proto::ServerStatus;

fn kb_field(text: &str, key: &str) -> Option<u64> {
    text.lines().find_map(|l| {
        let rest = l.strip_prefix(key)?.strip_prefix(':')?;
        rest.split_whitespace().next()?.parse::<u64>().ok()
    })
}

/// `(total_bytes, used_bytes)` where used = `MemTotal - MemAvailable`.
pub fn parse_meminfo(text: &str) -> (u64, u64) {
    let total = kb_field(text, "MemTotal").unwrap_or(0);
    let available = kb_field(text, "MemAvailable")
        .or_else(|| kb_field(text, "MemFree"))
        .unwrap_or(total);
    (
        total.saturating_mul(1024),
        total.saturating_sub(available).saturating_mul(1024),
    )
}

/// The 1-minute load average.
pub fn parse_loadavg(text: &str) -> f32 {
    text.split_whitespace()
        .next()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0)
}

/// Whole seconds since boot.
pub fn parse_uptime(text: &str) -> u64 {
    text.split_whitespace()
        .next()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v >= 0.0)
        .map_or(0, |v| v as u64)
}

/// `PRETTY_NAME` from os-release, without quotes. Falls back to "Linux".
pub fn parse_os_release(text: &str) -> String {
    text.lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .map(|v| v.trim().trim_matches(|c| c == '"' || c == '\'').to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "Linux".to_string())
}

/// Resident set size in bytes from `/proc/self/status`.
pub fn parse_vmrss(text: &str) -> u64 {
    kb_field(text, "VmRSS").unwrap_or(0).saturating_mul(1024)
}

// statvfs field widths differ by target (u32 on 32-bit), so the u64::from calls
// are needed there even though they are identity conversions on x86_64.
#[allow(clippy::useless_conversion)]
fn disk_usage(path: &Path) -> io::Result<(u64, u64)> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let mut st = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
    // SAFETY: `c_path` is a valid NUL-terminated string and `st` points to
    // writable memory of the right type; statvfs fully initialises it on success.
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), st.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: statvfs returned 0, so the struct is initialised.
    let st = unsafe { st.assume_init() };
    let unit = u64::from(st.f_frsize);
    let total = u64::from(st.f_blocks).saturating_mul(unit);
    let free = u64::from(st.f_bfree).saturating_mul(unit);
    Ok((total, total.saturating_sub(free)))
}

fn read(path: &str) -> io::Result<String> {
    std::fs::read_to_string(path)
}

/// Collect the current server status. `data_dir` selects the disk to report.
pub fn read_status(data_dir: &Path) -> io::Result<ServerStatus> {
    let (mem_total_bytes, mem_used_bytes) = parse_meminfo(&read("/proc/meminfo")?);
    let (disk_total_bytes, disk_used_bytes) = disk_usage(data_dir)?;
    Ok(ServerStatus {
        hostname: read("/proc/sys/kernel/hostname")
            .map(|h| h.trim().to_string())
            .unwrap_or_default(),
        os_pretty_name: read("/etc/os-release")
            .or_else(|_| read("/usr/lib/os-release"))
            .map(|t| parse_os_release(&t))
            .unwrap_or_else(|_| "Linux".to_string()),
        arch: std::env::consts::ARCH.to_string(),
        uptime_secs: parse_uptime(&read("/proc/uptime")?),
        load_1m: parse_loadavg(&read("/proc/loadavg")?),
        mem_total_bytes,
        mem_used_bytes,
        disk_total_bytes,
        disk_used_bytes,
        agent_rss_bytes: parse_vmrss(&read("/proc/self/status")?),
    })
}
