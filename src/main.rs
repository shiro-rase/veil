use anyhow::Result;
use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use veil::client::ClientAgent;
use veil::config::{ClientConfig, ControlConfig, NodeConfig};
use veil::control::ControlServer;
use veil::crypto::Keypair;
use veil::node::NodeAgent;

#[derive(Parser)]
#[command(name = "veil")]
#[command(version = "0.1.0")]
#[command(about = "Stealth overlay network with custom domains and reinforced WireGuard protocol")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Control {
        #[arg(short, long)]
        config: Option<PathBuf>,
        #[arg(short, long)]
        bind: Option<String>,
        #[arg(short, long)]
        secret: Option<String>,
    },
    Node {
        #[arg(short, long, default_value = "veil-node.yaml")]
        config: PathBuf,
    },
    Client {
        #[arg(short, long, default_value = "veil-client.yaml")]
        config: PathBuf,
    },
    Init {
        #[arg(short = 't', long, value_parser = ["node", "client", "control"])]
        role: String,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    Genkey,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Control { config, bind, secret } => {
            let mut cfg = if let Some(path) = config {
                ControlConfig::load_from_file(path)?
            } else if std::path::Path::new("veil-control.yaml").exists() {
                ControlConfig::load_from_file("veil-control.yaml")?
            } else {
                ControlConfig::sample()
            };

            if let Some(b) = bind {
                cfg.bind_addr = b;
            }
            if let Some(s) = secret {
                cfg.network_secret = s;
            }

            let server = ControlServer::new(cfg);
            server.run().await?;
        }

        Commands::Node { config } => {
            let cfg = NodeConfig::load_from_file(&config)?;
            let agent = NodeAgent::new(cfg);
            agent.run().await?;
        }

        Commands::Client { config } => {
            let cfg = ClientConfig::load_from_file(&config)?;
            let agent = ClientAgent::new(cfg)?;
            agent.run().await?;
        }

        Commands::Init { role, out } => {
            let (default_filename, yaml_content) = match role.as_str() {
                "node" => ("veil-node.yaml", serde_yaml::to_string(&NodeConfig::sample())?),
                "client" => ("veil-client.yaml", serde_yaml::to_string(&ClientConfig::sample())?),
                "control" => ("veil-control.yaml", serde_yaml::to_string(&ControlConfig::sample())?),
                _ => unreachable!(),
            };

            let target_path = out.unwrap_or_else(|| PathBuf::from(default_filename));
            fs::write(&target_path, yaml_content)?;
            println!("Configuration created at: {}", target_path.display());
        }

        Commands::Genkey => {
            let kp = Keypair::generate();
            let secret_token: [u8; 32] = rand::random();
            println!("Network Secret Token: {}", hex::encode(secret_token));
            println!("X25519 Public Key:    {}", hex::encode(kp.public.as_bytes()));
        }
    }

    Ok(())
}
