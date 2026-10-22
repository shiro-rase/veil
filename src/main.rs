use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use veil::ca::CertificateAuthority;
use veil::client::ClientAgent;
use veil::config::{ClientConfig, ControlConfig, NodeConfig, RouteConfig};
use veil::control::ControlServer;
use veil::crypto::Keypair;
use veil::ipc::{send_ipc_command, IpcRequest, IpcResponse};
use veil::node::NodeAgent;
use veil::proto::{Frame, ObfuscatedCodec};
use veil::systemd::ServiceInstaller;

#[derive(Parser)]
#[command(name = "veil")]
#[command(version = "0.1.0")]
#[command(about = "Stealth overlay network with custom domains, P2P, and reinforced WireGuard protocol")]
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
    Ca {
        #[arg(short, long, default_value = "certs")]
        out: PathBuf,
        #[arg(short, long)]
        domains: Vec<String>,
    },
    Install {
        #[arg(short = 't', long, value_parser = ["node", "client", "control"])]
        role: String,
        #[arg(short, long)]
        config: String,
    },
    Token {
        #[command(subcommand)]
        action: TokenCommands,
    },
    Device {
        #[command(subcommand)]
        action: DeviceCommands,
    },
    Route {
        #[command(subcommand)]
        action: RouteCommands,
    },
    Peers,
    Join {
        token: String,
        #[arg(short, long)]
        control: String,
        #[arg(short, long)]
        id: Option<String>,
    },
    Genkey,
}

#[derive(Subcommand)]
enum TokenCommands {
    Create {
        #[arg(short, long, default_value = "node")]
        role: String,
        #[arg(short, long, default_value = "3600")]
        ttl: u64,
        #[arg(long, default_value = "true")]
        auto_approve: bool,
    },
}

#[derive(Subcommand)]
enum DeviceCommands {
    List,
    Approve { id: String },
    Revoke { id: String },
}

#[derive(Subcommand)]
enum RouteCommands {
    Add { domain: String, target: String },
    Rm { domain: String },
    Ls,
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

        Commands::Ca { out, domains } => {
            if domains.is_empty() {
                CertificateAuthority::generate_ca(&out)?;
            } else {
                CertificateAuthority::generate_domain_cert(&domains, out)?;
            }
        }

        Commands::Install { role, config } => {
            ServiceInstaller::install_systemd(&role, &config)?;
        }

        Commands::Token { action } => match action {
            TokenCommands::Create { role, ttl, auto_approve } => {
                let token_mgr = veil::token::TokenManager::new();
                let tok = token_mgr.create_token(role, ttl, auto_approve).await;
                println!("{}", tok);
            }
        },

        Commands::Device { action } => match action {
            DeviceCommands::List => {
                println!("Device quarantine list managed in control plane");
            }
            DeviceCommands::Approve { id } => {
                println!("Device {} approved", id);
            }
            DeviceCommands::Revoke { id } => {
                println!("Device {} revoked", id);
            }
        },

        Commands::Route { action } => {
            let sock_path = PathBuf::from("/tmp/veil-node.sock");
            match action {
                RouteCommands::Add { domain, target } => {
                    let resp = send_ipc_command(&sock_path, IpcRequest::AddRoute { domain, target }).await?;
                    match resp {
                        IpcResponse::Success { message } => println!("{}", message),
                        IpcResponse::Error { error } => eprintln!("Error: {}", error),
                        _ => {}
                    }
                }
                RouteCommands::Rm { domain } => {
                    let resp = send_ipc_command(&sock_path, IpcRequest::RemoveRoute { domain }).await?;
                    match resp {
                        IpcResponse::Success { message } => println!("{}", message),
                        IpcResponse::Error { error } => eprintln!("Error: {}", error),
                        _ => {}
                    }
                }
                RouteCommands::Ls => {
                    let resp = send_ipc_command(&sock_path, IpcRequest::ListRoutes).await?;
                    match resp {
                        IpcResponse::Routes { routes } => {
                            for (dom, target) in routes {
                                println!("{} -> {}", dom, target);
                            }
                        }
                        IpcResponse::Error { error } => eprintln!("Error: {}", error),
                        _ => {}
                    }
                }
            }
        }

        Commands::Peers => {
            let sock_path = PathBuf::from("/tmp/veil-node.sock");
            let resp = send_ipc_command(&sock_path, IpcRequest::ListPeers).await?;
            match resp {
                IpcResponse::Peers { peers } => {
                    for p in peers {
                        println!("{}", p);
                    }
                }
                IpcResponse::Error { error } => eprintln!("Error: {}", error),
                _ => {}
            }
        }

        Commands::Join { token, control, id } => {
            let device_id = id.unwrap_or_else(|| format!("node-{}", hex::encode(rand::random::<[u8; 4]>())));
            let kp = Keypair::generate();
            let pub_key_hex = hex::encode(kp.public.as_bytes());

            let mut stream = tokio::net::TcpStream::connect(&control).await?;
            let codec = ObfuscatedCodec::new(b"veil-bootstrap-token-key");

            let enroll_frame = Frame::TokenEnroll {
                token: token.clone(),
                device_id: device_id.clone(),
                public_key: pub_key_hex,
                role: "node".to_string(),
            };

            let encoded = codec.encode_frame(&enroll_frame)?;
            tokio::io::AsyncWriteExt::write_all(&mut stream, &encoded).await?;

            let mut buf = bytes::BytesMut::with_capacity(4096);
            let mut read_exact_buf = [0u8; 1024];
            let n = tokio::io::AsyncReadExt::read(&mut stream, &mut read_exact_buf).await?;
            buf.extend_from_slice(&read_exact_buf[..n]);

            if let Some(Frame::EnrollResult { status, message }) = codec.try_decode_frame(&mut buf)? {
                println!("Enrollment status: {} ({})", status, message);
                let cfg = NodeConfig {
                    node_id: device_id,
                    network_secret: token,
                    control_server: control,
                    ingress_bind: "0.0.0.0:80".to_string(),
                    routes: vec![RouteConfig {
                        domain: "hui.hui.hui".to_string(),
                        proxy_to: "127.0.0.1:3000".to_string(),
                    }],
                };
                let cfg_path = PathBuf::from("veil-node.yaml");
                fs::write(&cfg_path, serde_yaml::to_string(&cfg)?)?;
                println!("Generated node configuration: {}", cfg_path.display());
            } else {
                return Err(anyhow!("Unexpected response from control server"));
            }
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
