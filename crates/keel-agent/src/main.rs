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
    Run {
        /// Path to the agent config file
        #[arg(long, default_value = "/etc/keel/agent.toml")]
        config: PathBuf,
        /// Data directory (overrides the config file)
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
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

fn run_agent(config: &Path, data_dir: Option<PathBuf>) -> anyhow::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .init();
    let mut cfg = AgentConfig::load(config)?;
    if let Some(d) = data_dir {
        cfg.data_dir = d;
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let mut term = signal(SignalKind::terminate())?;
        let shutdown = async move {
            tokio::select! {
                _ = term.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
        };
        keel_agent::server::run(cfg, keel_agent::server::system_clock(), shutdown).await
    })
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
        Cmd::Run { config, data_dir } => match run_agent(&config, data_dir) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("keel-agent failed: {e:#}");
                ExitCode::FAILURE
            }
        },
    }
}
