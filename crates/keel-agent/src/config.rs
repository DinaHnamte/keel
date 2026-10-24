use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentConfig {
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
}

#[derive(Deserialize, Default)]
struct RawConfig {
    listen: Option<SocketAddr>,
    data_dir: Option<PathBuf>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        AgentConfig {
            listen: SocketAddr::from(([0, 0, 0, 0], 7443)),
            data_dir: PathBuf::from("/var/lib/keel"),
        }
    }
}

impl AgentConfig {
    /// Load config from a TOML file. A missing file yields the defaults.
    pub fn load(path: &Path) -> Result<AgentConfig> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(AgentConfig::default());
            }
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let raw: RawConfig =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        let d = AgentConfig::default();
        Ok(AgentConfig {
            listen: raw.listen.unwrap_or(d.listen),
            data_dir: raw.data_dir.unwrap_or(d.data_dir),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_gives_defaults() {
        let c = AgentConfig::load(Path::new("/nonexistent/keel/agent.toml")).unwrap();
        assert_eq!(c.listen.to_string(), "0.0.0.0:7443");
        assert_eq!(c.data_dir, PathBuf::from("/var/lib/keel"));
    }

    #[test]
    fn partial_file_overrides() {
        let dir = std::env::temp_dir().join(format!("keel-cfg-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("agent.toml");
        std::fs::write(&p, "listen = \"127.0.0.1:9000\"\n").unwrap();
        let c = AgentConfig::load(&p).unwrap();
        assert_eq!(c.listen.to_string(), "127.0.0.1:9000");
        assert_eq!(c.data_dir, PathBuf::from("/var/lib/keel"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn invalid_file_errors() {
        let dir = std::env::temp_dir().join(format!("keel-cfg-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("agent.toml");
        std::fs::write(&p, "listen = 5\n").unwrap();
        assert!(AgentConfig::load(&p).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
