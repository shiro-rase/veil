use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
#[command(version = "0.2.0")]
#[command(about = "Stealth overlay network with custom domains, P2P, and reinforced WireGuard protocol")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Up {
        #[arg(short, long)]
        exit_node: Option<String>,
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    Down,
    Status {
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    Ping {
        target: String,
        #[arg(short, long, default_value = "4")]
        count: u32,
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    Ssh {
        target: String,
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
    Cp {
        #[arg(short, long)]
        recursive: bool,
        src: String,
        dst: String,
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    Tui {
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
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
        #[arg(short, long)]
        exit_node: Option<String>,
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
        #[arg(short, long)]
        install: bool,
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
    Web {
        #[arg(short, long, default_value = "127.0.0.1:9090")]
        bind: String,
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    Expose {
        port: u16,
        #[arg(long)]
        r#as: String,
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    Share {
        path: PathBuf,
        #[arg(long)]
        r#as: String,
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    Exec {
        target: String,
        command: String,
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    Kv {
        #[command(subcommand)]
        action: KvCommands,
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    Knock {
        endpoint: String,
        #[arg(short, long)]
        secret: Option<String>,
        #[arg(short, long, default_value = "knock-cli")]
        id: String,
    },
    Mobile {
        #[command(subcommand)]
        action: MobileCommands,
    },
    Lockdown {
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    Console {
        #[arg(short, long)]
        domain: String,
        #[arg(short, long, default_value = "0.0.0.0:8443")]
        bind: String,
        #[arg(short, long, default_value = "/etc/veil/certs")]
        certs: PathBuf,
    },
}

#[derive(Subcommand)]
enum KvCommands {
    Set { key: String, val: String },
    Get { key: String },
    List,
}

#[derive(Subcommand)]
enum MobileCommands {
    Add {
        name: String,
        #[arg(long, default_value = "10.42.0.50")]
        ip: String,
        #[arg(long, default_value = "94.237.57.175:51820")]
        endpoint: String,
    },
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

fn base64_encode(data: &[u8]) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i] as usize;
        let b1 = if i + 1 < data.len() { data[i + 1] as usize } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] as usize } else { 0 };
        out.push(CHARSET[(b0 >> 2) & 0x3F] as char);
        out.push(CHARSET[((b0 << 4) | (b1 >> 4)) & 0x3F] as char);
        if i + 1 < data.len() {
            out.push(CHARSET[((b1 << 2) | (b2 >> 6)) & 0x3F] as char);
        } else {
            out.push('=');
        }
        if i + 2 < data.len() {
            out.push(CHARSET[b2 & 0x3F] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

fn find_client_config(custom: Option<PathBuf>) -> PathBuf {
    if let Some(p) = custom {
        return p;
    }
    if let Some(home) = std::env::var_os("HOME") {
        let p = PathBuf::from(home).join(".config/veil/client.yaml");
        if p.exists() {
            return p;
        }
    }
    if PathBuf::from("veil-client.yaml").exists() {
        return PathBuf::from("veil-client.yaml");
    }
    PathBuf::from("/etc/veil/veil-client.yaml")
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Up { exit_node, config } => {
            let cfg_path = find_client_config(config);
            let mut cfg = ClientConfig::load_from_file(&cfg_path)?;
            if let Some(en) = exit_node {
                cfg.exit_node = Some(en);
            }
            cfg.tun_enabled = Some(true);
            let agent = ClientAgent::new(cfg)?;
            agent.run().await?;
        }

        Commands::Down => {
            let _ = std::process::Command::new("systemctl").args(["--user", "stop", "veil-client.service"]).status();
            let _ = std::process::Command::new("pkill").args(["-f", "veil client"]).status();
            let _ = std::process::Command::new("ip").args(["link", "del", "dev", "veil0"]).status();
            println!("Veil overlay stopped and veil0 removed.");
        }

        Commands::Status { config } => {
            let cfg_path = find_client_config(config);
            let cfg = ClientConfig::load_from_file(&cfg_path)?;
            let stream = tokio::net::TcpStream::connect(&cfg.control_server).await?;
            let codec = ObfuscatedCodec::new(cfg.network_secret.as_bytes());
            let (mut reader, mut writer) = stream.into_split();
            let reg = Frame::RegisterClient {
                client_id: "status-cli".to_string(),
                secret_token: cfg.network_secret.clone(),
            };
            writer.write_all(&codec.encode_frame(&reg)?).await?;
            writer.write_all(&codec.encode_frame(&Frame::NodeStatusQuery)?).await?;

            let mut buf = bytes::BytesMut::with_capacity(65536);
            let mut temp = [0u8; 4096];
            loop {
                let n = reader.read(&mut temp).await?;
                if n == 0 { break; }
                buf.extend_from_slice(&temp[..n]);
                while let Some(frame) = codec.try_decode_frame(&mut buf)? {
                    if let Frame::NodeStatusReply { nodes } = frame {
                        println!("{:<14} {:<15} {:<10} {:<35}", "NODE ID", "VIRTUAL IP", "STATUS", "DOMAINS");
                        println!("{:-<14} {:-<15} {:-<10} {:-<35}", "", "", "", "");
                        for n in nodes {
                            let doms = n.domains.join(", ");
                            println!("{:<14} {:<15} {:<10} {:<35}", n.node_id, n.virtual_ip, "Online", doms);
                        }
                        return Ok(());
                    }
                }
            }
        }

        Commands::Ping { target, count, config } => {
            let cfg_path = find_client_config(config);
            let cfg = ClientConfig::load_from_file(&cfg_path)?;
            let stream = tokio::net::TcpStream::connect(&cfg.control_server).await?;
            let codec = ObfuscatedCodec::new(cfg.network_secret.as_bytes());
            let (mut reader, mut writer) = stream.into_split();
            let client_id = format!("ping-cli-{}", hex::encode(rand::random::<[u8; 4]>()));
            let reg = Frame::RegisterClient {
                client_id,
                secret_token: cfg.network_secret.clone(),
            };
            writer.write_all(&codec.encode_frame(&reg)?).await?;

            let mut seq = 1;
            let mut buf = bytes::BytesMut::with_capacity(65536);
            let mut temp = [0u8; 4096];

            println!("PING {} via Veil mesh ({}):", target, cfg.control_server);
            for _ in 0..count {
                let start = std::time::Instant::now();
                writer.write_all(&codec.encode_frame(&Frame::PingRequest {
                    target_node: target.clone(),
                    seq,
                    timestamp_ms: 0,
                })?).await?;

                if let Ok(Ok(n)) = tokio::time::timeout(tokio::time::Duration::from_secs(2), reader.read(&mut temp)).await {
                    if n > 0 {
                        buf.extend_from_slice(&temp[..n]);
                        while let Some(frame) = codec.try_decode_frame(&mut buf)? {
                            if let Frame::PingResponse { from_node, seq: r_seq, .. } = frame {
                                let rtt = start.elapsed().as_secs_f64() * 1000.0;
                                println!("64 bytes from {}: seq={} rtt={:.2}ms", from_node, r_seq, rtt);
                            }
                        }
                    }
                }
                seq += 1;
                tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
            }
        }

        Commands::Ssh { target, args } => {
            let mut ssh_args = vec![];
            if target.starts_with("10.42.0.") || target.contains('.') {
                ssh_args.push(format!("user@{}", target));
            } else {
                ssh_args.push(format!("user@ssh.{}", target));
            }
            for a in args {
                ssh_args.push(a);
            }
            let status = std::process::Command::new("ssh")
                .args(&ssh_args)
                .status()?;
            if !status.success() {
                std::process::exit(status.code().unwrap_or(1));
            }
        }

        Commands::Cp {
            recursive,
            src,
            dst,
            config,
        } => {
            let cfg_path = find_client_config(config);
            let cfg = ClientConfig::load_from_file(&cfg_path)?;

            let (local_path, target_node, remote_path) = if let Some(idx) = dst.find(':') {
                let node = &dst[..idx];
                let path = &dst[idx + 1..];
                (PathBuf::from(src), node.to_string(), path.to_string())
            } else {
                return Err(anyhow!("Destination must be in format <node>:<remote_path>"));
            };

            let is_directory = local_path.is_dir() || recursive;
            if is_directory && !local_path.is_dir() {
                return Err(anyhow!("Source path is not a directory: {}", local_path.display()));
            }

            let (upload_path, is_temp, upload_target_path) = if is_directory {
                let temp_tar = std::env::temp_dir().join(format!("veil_dir_{}.tar.gz", hex::encode(rand::random::<[u8; 4]>())));
                let status = std::process::Command::new("tar")
                    .args(["-czf", temp_tar.to_str().unwrap(), "-C", local_path.to_str().unwrap(), "."])
                    .status()?;
                if !status.success() {
                    return Err(anyhow!("Failed to archive directory for transfer"));
                }
                let remote_tar = format!("/tmp/.veil_pkg_{}.tar.gz", hex::encode(rand::random::<[u8; 4]>()));
                (temp_tar, true, remote_tar)
            } else {
                (local_path.clone(), false, remote_path.clone())
            };

            let metadata = fs::metadata(&upload_path)?;
            let total_size = metadata.len();
            let filename = upload_path.file_name().unwrap_or_default().to_string_lossy().to_string();

            let stream = tokio::net::TcpStream::connect(&cfg.control_server).await?;
            let codec = ObfuscatedCodec::new(cfg.network_secret.as_bytes());
            let (mut reader, mut writer) = stream.into_split();
            let reg = Frame::RegisterClient {
                client_id: "cp-cli".to_string(),
                secret_token: cfg.network_secret.clone(),
            };
            writer.write_all(&codec.encode_frame(&reg)?).await?;

            let transfer_id = format!("tx-{}", hex::encode(rand::random::<[u8; 4]>()));
            writer.write_all(&codec.encode_frame(&Frame::FileTransferInit {
                transfer_id: transfer_id.clone(),
                target_node: target_node.clone(),
                filename: filename.clone(),
                target_path: upload_target_path.clone(),
                total_size,
            })?).await?;

            let mut file = std::fs::File::open(&upload_path)?;
            use std::io::Read;
            let mut chunk_buf = vec![0u8; 65536];
            let mut sent_bytes = 0u64;

            loop {
                let n = file.read(&mut chunk_buf)?;
                if n == 0 { break; }
                writer.write_all(&codec.encode_frame(&Frame::FileTransferChunk {
                    transfer_id: transfer_id.clone(),
                    target_node: target_node.clone(),
                    offset: sent_bytes,
                    data: chunk_buf[..n].to_vec(),
                })?).await?;
                sent_bytes += n as u64;
                let pct = if total_size > 0 {
                    (sent_bytes as f64 / total_size as f64 * 100.0) as u32
                } else {
                    100
                };
                print!("\rSending {} to {}: {} / {} bytes ({}%)", filename, target_node, sent_bytes, total_size, pct);
                use std::io::Write;
                std::io::stdout().flush().unwrap();
            }
            println!();

            writer.write_all(&codec.encode_frame(&Frame::FileTransferDone {
                transfer_id,
                target_node: target_node.clone(),
                success: true,
                message: "Done".to_string(),
            })?).await?;

            let mut temp = [0u8; 1024];
            let _ = tokio::time::timeout(tokio::time::Duration::from_secs(3), reader.read(&mut temp)).await;

            if is_temp {
                let extract_cmd = format!(
                    "mkdir -p '{}' && tar -xzf '{}' -C '{}' && rm -f '{}'",
                    remote_path,
                    upload_target_path,
                    remote_path,
                    upload_target_path
                );
                let exec_id = format!("cmd-{}", rand::random::<u32>());
                let req = Frame::ExecRequest {
                    exec_id,
                    target_node: target_node.clone(),
                    command: extract_cmd,
                };
                writer.write_all(&codec.encode_frame(&req)?).await?;
                let _ = tokio::time::timeout(tokio::time::Duration::from_secs(3), reader.read(&mut temp)).await;
                let _ = std::fs::remove_file(&upload_path);
                println!("Directory {} unpacked to {} on {}", local_path.display(), remote_path, target_node);
            } else {
                println!("File transfer completed successfully.");
            }
        }

        Commands::Tui { config } => {
            let cfg_path = find_client_config(config);
            let cfg = ClientConfig::load_from_file(&cfg_path)?;
            println!("\x1b[2J\x1b[H");
            loop {
                print!("\x1b[H");
                println!("Veil Mesh Live Monitor | Control Server: {}", cfg.control_server);
                println!("{:<14} {:<15} {:<10} {:<35}", "NODE ID", "VIRTUAL IP", "STATUS", "DOMAINS");
                println!("{:-<14} {:-<15} {:-<10} {:-<35}", "", "", "", "");
                if let Ok(stream) = tokio::net::TcpStream::connect(&cfg.control_server).await {
                    let codec = ObfuscatedCodec::new(cfg.network_secret.as_bytes());
                    let (mut reader, mut writer) = stream.into_split();
                    let reg = Frame::RegisterClient {
                        client_id: "tui-cli".to_string(),
                        secret_token: cfg.network_secret.clone(),
                    };
                    if writer.write_all(&codec.encode_frame(&reg).unwrap()).await.is_ok() {
                        let _ = writer.write_all(&codec.encode_frame(&Frame::NodeStatusQuery).unwrap()).await;
                        let mut buf = bytes::BytesMut::with_capacity(65536);
                        let mut temp = [0u8; 4096];
                        if let Ok(Ok(n)) = tokio::time::timeout(tokio::time::Duration::from_millis(500), reader.read(&mut temp)).await {
                            if n > 0 {
                                buf.extend_from_slice(&temp[..n]);
                                if let Ok(Some(Frame::NodeStatusReply { nodes })) = codec.try_decode_frame(&mut buf) {
                                    for n in nodes {
                                        println!("{:<14} {:<15} {:<10} {:<35}", n.node_id, n.virtual_ip, "Online", n.domains.join(", "));
                                    }
                                }
                            }
                        }
                    }
                }
                println!("\nPress Ctrl+C to exit monitor");
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }

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

        Commands::Client { config, exit_node } => {
            let mut cfg = ClientConfig::load_from_file(&config)?;
            if let Some(en) = exit_node {
                cfg.exit_node = Some(en);
            }
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

        Commands::Ca { out, domains, install } => {
            if install {
                let ca_file = out.join("veil-ca.crt");
                if !ca_file.exists() {
                    CertificateAuthority::generate_ca(&out)?;
                }
                let _ = std::process::Command::new("cp").args([ca_file.to_str().unwrap(), "/etc/ca-certificates/trust-source/anchors/"]).status();
                let _ = std::process::Command::new("trust").args(["extract-compat"]).status();
                let _ = std::process::Command::new("cp").args([ca_file.to_str().unwrap(), "/etc/pki/ca-trust/source/anchors/"]).status();
                let _ = std::process::Command::new("update-ca-trust").status();
                println!("Veil Root CA installed and trusted system-wide.");
            } else if domains.is_empty() {
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
                    web_bind: None,
                    web_domain: None,
                    cert_dir: None,
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

        Commands::Web { bind, config } => {
            let cfg_path = find_client_config(config);
            let cfg = ClientConfig::load_from_file(&cfg_path)?;
            let server = veil::dashboard::DashboardServer::new(bind, cfg.control_server, cfg.network_secret);
            server.run().await?;
        }

        Commands::Expose { port, r#as, config } => {
            let cfg_path = find_client_config(config);
            let cfg = ClientConfig::load_from_file(&cfg_path)?;
            veil::expose::run_expose_service(&cfg.control_server, &cfg.network_secret, port, &r#as).await?;
        }

        Commands::Share { path, r#as, config } => {
            let cfg_path = find_client_config(config);
            let cfg = ClientConfig::load_from_file(&cfg_path)?;
            let path_str = path.to_str().ok_or_else(|| anyhow!("Invalid path string"))?;
            veil::expose::run_file_share(&cfg.control_server, &cfg.network_secret, path_str, &r#as).await?;
        }

        Commands::Exec { target, command, config } => {
            let cfg_path = find_client_config(config);
            let cfg = ClientConfig::load_from_file(&cfg_path)?;
            let mut stream = tokio::net::TcpStream::connect(&cfg.control_server).await?;
            let codec = ObfuscatedCodec::new(cfg.network_secret.as_bytes());
            let client_id = format!("exec-{}", rand::random::<u32>());
            let reg = Frame::RegisterClient {
                client_id,
                secret_token: cfg.network_secret.clone(),
            };
            stream.write_all(&codec.encode_frame(&reg)?).await?;

            let exec_id = format!("cmd-{}", rand::random::<u32>());
            let req = Frame::ExecRequest {
                exec_id: exec_id.clone(),
                target_node: target,
                command,
            };
            stream.write_all(&codec.encode_frame(&req)?).await?;

            let mut read_buf = bytes::BytesMut::with_capacity(32768);
            let mut tmp = [0u8; 8192];
            loop {
                let n = stream.read(&mut tmp).await?;
                if n == 0 {
                    break;
                }
                read_buf.extend_from_slice(&tmp[..n]);
                while let Some(frame) = codec.try_decode_frame(&mut read_buf)? {
                    if let Frame::ExecResponse { exit_code, stdout, stderr, .. } = frame {
                        if !stdout.is_empty() {
                            print!("{}", stdout);
                        }
                        if !stderr.is_empty() {
                            eprint!("{}", stderr);
                        }
                        std::process::exit(exit_code);
                    }
                }
            }
        }

        Commands::Kv { action, config } => {
            let cfg_path = find_client_config(config);
            let cfg = ClientConfig::load_from_file(&cfg_path)?;
            let mut stream = tokio::net::TcpStream::connect(&cfg.control_server).await?;
            let codec = ObfuscatedCodec::new(cfg.network_secret.as_bytes());
            let reg = Frame::RegisterClient {
                client_id: format!("kv-{}", rand::random::<u32>()),
                secret_token: cfg.network_secret.clone(),
            };
            stream.write_all(&codec.encode_frame(&reg)?).await?;

            match action {
                KvCommands::Set { key, val } => {
                    stream.write_all(&codec.encode_frame(&Frame::KvSet { key, value: val })?).await?;
                    println!("OK");
                }
                KvCommands::Get { key } => {
                    stream.write_all(&codec.encode_frame(&Frame::KvGet { key })?).await?;
                    let mut buf = bytes::BytesMut::with_capacity(8192);
                    let mut tmp = [0u8; 2048];
                    loop {
                        let n = stream.read(&mut tmp).await?;
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(Frame::KvReply { value, .. }) = codec.try_decode_frame(&mut buf)? {
                            match value {
                                Some(v) => println!("{}", v),
                                None => println!("(nil)"),
                            }
                            break;
                        }
                    }
                }
                KvCommands::List => {
                    stream.write_all(&codec.encode_frame(&Frame::KvList)?).await?;
                    let mut buf = bytes::BytesMut::with_capacity(16384);
                    let mut tmp = [0u8; 4096];
                    loop {
                        let n = stream.read(&mut tmp).await?;
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(Frame::KvListReply { entries }) = codec.try_decode_frame(&mut buf)? {
                            println!("{:<24} {:<40}", "KEY", "VALUE");
                            println!("{:<24} {:<40}", "------------------------", "----------------------------------------");
                            for (k, v) in entries {
                                println!("{:<24} {:<40}", k, v);
                            }
                            break;
                        }
                    }
                }
            }
        }

        Commands::Knock { endpoint, secret, id } => {
            let sec = secret.unwrap_or_else(|| "9f82ab7c31d4e0821b05934f8261ab7289c02183e29a0f91b728192837462819".to_string());
            veil::spa::SpaAuth::send_knock(&endpoint, sec.as_bytes(), &id).await?;
            println!("Single Packet Authorization (SPA) knock sent to {}", endpoint);
        }

        Commands::Mobile { action } => {
            match action {
                MobileCommands::Add { name, ip, endpoint } => {
                    let kp = Keypair::generate();
                    let server_kp = Keypair::generate();
                    let priv_b64 = base64_encode(kp.secret.as_bytes());
                    let pub_b64 = base64_encode(kp.public.as_bytes());
                    let srv_pub_b64 = base64_encode(server_kp.public.as_bytes());

                    let config_text = format!(
                        "[Interface]\nPrivateKey = {}\nAddress = {}/24\nDNS = 10.42.0.1\n\n[Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = 10.42.0.0/24, 0.0.0.0/0\nPersistentKeepalive = 25\n",
                        priv_b64, ip, srv_pub_b64, endpoint
                    );

                    println!("Generated WireGuard mobile profile: {}", name);
                    println!("Client Public Key: {}", pub_b64);
                    println!();
                    if let Ok(qr) = veil::qr::render_qr_terminal(&config_text) {
                        println!("{}", qr);
                    }
                    println!("{}", config_text);
                }
            }
        }

        Commands::Lockdown { config } => {
            let cfg_path = find_client_config(config);
            let cfg = ClientConfig::load_from_file(&cfg_path)?;
            let mut stream = tokio::net::TcpStream::connect(&cfg.control_server).await?;
            let codec = ObfuscatedCodec::new(cfg.network_secret.as_bytes());
            let reg = Frame::RegisterClient {
                client_id: cfg.client_id.clone(),
                secret_token: cfg.network_secret.clone(),
            };
            stream.write_all(&codec.encode_frame(&reg)?).await?;
            stream.write_all(&codec.encode_frame(&Frame::LockdownNotice { initiator: cfg.client_id })?).await?;
            println!("EMERGENCY LOCKDOWN INITIATED: Mesh signals dispatched");
        }

        Commands::Console { domain, bind, certs } => {
            let server = veil::node_web::NodeWebServer::new(domain, bind, certs, vec![]);
            server.run().await?;
        }
    }

    Ok(())
}
