use crate::config::NodeConfig;
use crate::ingress::IngressRouter;
use crate::proto::{Frame, ObfuscatedCodec};
use anyhow::{anyhow, Result};
use bytes::BytesMut;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{sleep, Duration};

pub struct NodeAgent {
    config: Arc<NodeConfig>,
    router: IngressRouter,
    active_local_conns: Arc<RwLock<HashMap<u64, mpsc::UnboundedSender<Vec<u8>>>>>,
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

        loop {
            match self.connect_and_serve().await {
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

    async fn connect_and_serve(&self) -> Result<()> {
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
            let n = reader.read_buf(&mut read_buf).await?;
            if n == 0 {
                return Err(anyhow!("Control server closed socket"));
            }

            while let Some(frame) = codec.try_decode_frame(&mut read_buf)? {
                self.handle_frame(frame, &tx).await?;
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
                } else {
                    eprintln!("Registration rejected by control plane: {}", message);
                }
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
