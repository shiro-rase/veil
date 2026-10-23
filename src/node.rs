use crate::config::NodeConfig;
use crate::ingress::IngressRouter;
use crate::ipc::{IpcRequest, IpcServer};
use crate::proto::{Frame, ObfuscatedCodec};
use crate::tun::TunDevice;
use anyhow::{anyhow, Result};
use bytes::BytesMut;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{sleep, Duration};

pub struct NodeAgent {
    config: Arc<NodeConfig>,
    router: IngressRouter,
    active_local_conns: Arc<RwLock<HashMap<u64, mpsc::UnboundedSender<Vec<u8>>>>>,
    active_transfers: Arc<RwLock<HashMap<String, File>>>,
    tun_tx: Arc<RwLock<Option<mpsc::UnboundedSender<Vec<u8>>>>>,
}

impl NodeAgent {
    pub fn new(config: NodeConfig) -> Self {
        let mut route_map = HashMap::new();
        for r in &config.routes {
            route_map.insert(r.domain.clone(), r.proxy_to.clone());
        }
        let router = IngressRouter::new(route_map);
        Self {
            config: Arc::new(config),
            router,
            active_local_conns: Arc::new(RwLock::new(HashMap::new())),
            active_transfers: Arc::new(RwLock::new(HashMap::new())),
            tun_tx: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn run(&self) -> Result<()> {
        let router = self.router.clone();
        let ingress_addr = self.config.ingress_bind.clone();
        tokio::spawn(async move {
            if let Ok(addr) = ingress_addr.parse() {
                let _ = router.start(addr).await;
            }
        });

        let (ipc_tx, mut ipc_rx) = mpsc::unbounded_channel::<IpcRequest>();
        let ipc_sock_path = PathBuf::from("/tmp/veil-node.sock");
        let _ = IpcServer::start(ipc_sock_path, self.router.clone(), Some(ipc_tx)).await;

        loop {
            match self.connect_and_serve(&mut ipc_rx).await {
                Ok(_) => {
                    println!("Node disconnected cleanly, reconnecting in 2s...");
                }
                Err(e) => {
                    eprintln!("Connection to control lost: {e}, retrying in 3s...");
                }
            }
            sleep(Duration::from_secs(3)).await;
        }
    }

    async fn connect_and_serve(&self, ipc_rx: &mut mpsc::UnboundedReceiver<IpcRequest>) -> Result<()> {
        let stream = TcpStream::connect(&self.config.control_server).await?;
        println!("Connected to Veil control plane at {}", self.config.control_server);

        let (mut reader, mut writer) = stream.into_split();
        let codec = Arc::new(ObfuscatedCodec::new(self.config.network_secret.as_bytes()));
        let (tx, mut rx) = mpsc::unbounded_channel::<Frame>();

        let domains: Vec<String> = self.config.routes.iter().map(|r| r.domain.clone()).collect();
        let register_frame = Frame::RegisterNode {
            node_id: self.config.node_id.clone(),
            secret_token: self.config.network_secret.clone(),
            domains,
            virtual_ip: None,
        };

        let encoded = codec.encode_frame(&register_frame)?;
        writer.write_all(&encoded).await?;

        let codec_tx = codec.clone();
        tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                if let Ok(encoded) = codec_tx.encode_frame(&frame) {
                    if writer.write_all(&encoded).await.is_err() {
                        break;
                    }
                }
            }
        });

        let tx_hb = tx.clone();
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(15)).await;
                if tx_hb.send(Frame::Heartbeat).is_err() {
                    break;
                }
            }
        });

        let mut read_buf = BytesMut::with_capacity(65536);
        loop {
            tokio::select! {
                res = reader.read_buf(&mut read_buf) => {
                    let n = res?;
                    if n == 0 {
                        return Err(anyhow!("Control server closed socket"));
                    }
                    while let Some(frame) = codec.try_decode_frame(&mut read_buf)? {
                        self.handle_frame(frame, &tx).await?;
                    }
                }
                Some(ipc_cmd) = ipc_rx.recv() => {
                    match ipc_cmd {
                        IpcRequest::AddRoute { domain, .. } => {
                            let _ = tx.send(Frame::DynamicRouteAdd {
                                domain,
                                target_port: 80,
                            });
                        }
                        IpcRequest::RemoveRoute { domain } => {
                            let _ = tx.send(Frame::DynamicRouteRemove { domain });
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    async fn handle_frame(&self, frame: Frame, to_control: &mpsc::UnboundedSender<Frame>) -> Result<()> {
        match frame {
            Frame::RegisterAck {
                virtual_ip,
                success,
                message,
                ..
            } => {
                if success {
                    println!("Node registered successfully. Virtual IP: {}", virtual_ip);
                    for r in &self.config.routes {
                        println!(" -> Domain '{}' bound to '{}'", r.domain, r.proxy_to);
                    }

                    if let Ok(ip) = virtual_ip.parse::<Ipv4Addr>() {
                        match TunDevice::create("veil0", ip) {
                            Ok(mut tun) => {
                                println!("Virtual interface veil0 active with IP {}", ip);
                                let _ = TunDevice::enable_exit_node_forwarding();
                                let (t_in_tx, mut t_in_rx) = mpsc::unbounded_channel::<Vec<u8>>();
                                *self.tun_tx.write().await = Some(t_in_tx);

                                let to_ctrl_packet = to_control.clone();
                                let node_vip = virtual_ip.clone();
                                tokio::spawn(async move {
                                    let mut buf = [0u8; 4096];
                                    loop {
                                        tokio::select! {
                                            read_res = tun.read_packet(&mut buf) => {
                                                if let Ok(n) = read_res {
                                                    if n >= 20 {
                                                        let dst = format!("{}.{}.{}.{}", buf[16], buf[17], buf[18], buf[19]);
                                                        let _ = to_ctrl_packet.send(Frame::IpPacket {
                                                            src_ip: node_vip.clone(),
                                                            dst_ip: dst,
                                                            payload: buf[..n].to_vec(),
                                                        });
                                                    }
                                                } else {
                                                    break;
                                                }
                                            }
                                            Some(packet_to_write) = t_in_rx.recv() => {
                                                let _ = tun.write_packet(&packet_to_write).await;
                                            }
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                eprintln!("TUN device initialization skipped: {}", e);
                            }
                        }
                    }
                } else {
                    eprintln!("Registration rejected by control plane: {}", message);
                }
            }

            Frame::IpPacket { payload, .. } => {
                let lock = self.tun_tx.read().await;
                if let Some(ref tx) = *lock {
                    let _ = tx.send(payload);
                }
            }

            Frame::PingRequest { seq, timestamp_ms, .. } => {
                let _ = to_control.send(Frame::PingResponse {
                    from_node: self.config.node_id.clone(),
                    seq,
                    timestamp_ms,
                });
            }

            Frame::FileTransferInit { transfer_id, filename, target_path, .. } => {
                let path = if target_path.is_empty() {
                    PathBuf::from(format!("/tmp/{}", filename))
                } else {
                    PathBuf::from(target_path)
                };
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if let Ok(file) = File::create(&path) {
                    self.active_transfers.write().await.insert(transfer_id, file);
                    println!("Receiving file {} -> {}", filename, path.display());
                }
            }

            Frame::FileTransferChunk { transfer_id, data, .. } => {
                let mut transfers = self.active_transfers.write().await;
                if let Some(file) = transfers.get_mut(&transfer_id) {
                    let _ = file.write_all(&data);
                }
            }

            Frame::FileTransferDone { transfer_id, .. } => {
                let mut transfers = self.active_transfers.write().await;
                if let Some(mut file) = transfers.remove(&transfer_id) {
                    let _ = file.flush();
                    println!("File transfer {} complete", transfer_id);
                    let _ = to_control.send(Frame::FileTransferDone {
                        transfer_id,
                        target_node: self.config.node_id.clone(),
                        success: true,
                        message: "Success".to_string(),
                    });
                }
            }

            Frame::ExecRequest { exec_id, command, .. } => {
                let to_ctrl = to_control.clone();
                let node_id = self.config.node_id.clone();
                tokio::spawn(async move {
                    let res = crate::exec::RemoteExecutor::execute(&command, 30).await.unwrap_or(crate::exec::ExecResult {
                        exit_code: 1,
                        stdout: String::new(),
                        stderr: "Execution failed".to_string(),
                    });
                    let _ = to_ctrl.send(Frame::ExecResponse {
                        exec_id,
                        from_node: node_id,
                        exit_code: res.exit_code,
                        stdout: res.stdout,
                        stderr: res.stderr,
                    });
                });
            }

            Frame::LockdownNotice { initiator } => {
                println!("Emergency lockdown triggered by {}. Isolating connections.", initiator);
                self.active_local_conns.write().await.clear();
            }

            Frame::StreamOpen {
                stream_id,
                domain,
                ..
            } => {
                if let Some(target) = self.router.get_target(&domain).await {
                    let to_ctrl = to_control.clone();
                    let conns = self.active_local_conns.clone();

                    match TcpStream::connect(&target).await {
                        Ok(backend) => {
                            let (mut b_read, mut b_write) = backend.into_split();
                            let (tx_to_backend, mut rx_to_backend) = mpsc::unbounded_channel::<Vec<u8>>();

                            conns.write().await.insert(stream_id, tx_to_backend);

                            tokio::spawn(async move {
                                while let Some(chunk) = rx_to_backend.recv().await {
                                    if b_write.write_all(&chunk).await.is_err() {
                                        break;
                                    }
                                }
                                let _ = b_write.shutdown().await;
                            });

                            let conns_cleanup = conns.clone();
                            tokio::spawn(async move {
                                let mut buf = [0u8; 8192];
                                loop {
                                    match b_read.read(&mut buf).await {
                                        Ok(n) if n > 0 => {
                                            let _ = to_ctrl.send(Frame::StreamData {
                                                stream_id,
                                                payload: buf[..n].to_vec(),
                                            });
                                        }
                                        _ => break,
                                    }
                                }
                                let _ = to_ctrl.send(Frame::StreamClose { stream_id });
                                conns_cleanup.write().await.remove(&stream_id);
                            });
                        }
                        Err(e) => {
                            eprintln!("Failed to connect to local target {}: {}", target, e);
                            let _ = to_control.send(Frame::StreamClose { stream_id });
                        }
                    }
                }
            }

            Frame::StreamData { stream_id, payload } => {
                let conns = self.active_local_conns.read().await;
                if let Some(target_tx) = conns.get(&stream_id) {
                    let _ = target_tx.send(payload);
                }
            }

            Frame::StreamClose { stream_id } => {
                self.active_local_conns.write().await.remove(&stream_id);
            }

            Frame::Heartbeat => {}
            _ => {}
        }
        Ok(())
    }
}
