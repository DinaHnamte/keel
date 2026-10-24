use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use keel_agent::config::AgentConfig;
use keel_agent::init::init;

#[derive(Parser)]
#[command(name = "keel-agent", version, about = "Keel server agent")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Set up the agent and print its fingerprint and a one-time pairing code
    Init {
        /// Public host name or IP address that desktops will connect to
        #[arg(long)]
        host: String,
        /// Path to the agent config file
        #[arg(long, default_value = "/etc/keel/agent.toml")]
        config: PathBuf,
        /// Data directory (overrides the config file)
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Run the agent
    Run,
}

fn run_init(host: &str, config: &Path, data_dir: Option<PathBuf>) -> anyhow::Result<()> {
    let mut cfg = AgentConfig::load(config)?;
    if let Some(d) = data_dir {
        cfg.data_dir = d;
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let out = init(&cfg, host, now)?;
    println!("fingerprint={}", out.fingerprint);
    println!("pairing_code={}", out.pairing_code.encode());
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Cmd::Init {
            host,
            config,
            data_dir,
        } => match run_init(&host, &config, data_dir) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("keel-agent init failed: {e:#}");
                ExitCode::FAILURE
            }
        },
        Cmd::Run => {
            eprintln!("not implemented yet");
            ExitCode::FAILURE
        }
    }
}
