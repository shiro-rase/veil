use crate::acl::AclEngine;
use crate::config::ControlConfig;
use crate::proto::{Frame, ObfuscatedCodec, RouteEntry};
use crate::token::{DeviceStatus, TokenManager};
use anyhow::{anyhow, Result};
use bytes::BytesMut;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};

struct ActiveNode {
    node_id: String,
    virtual_ip: String,
    domains: Vec<String>,
    sender: mpsc::UnboundedSender<Frame>,
}

struct ActiveClient {
    _client_id: String,
    sender: mpsc::UnboundedSender<Frame>,
}

#[derive(Clone)]
struct StreamPair {
    client_tx: mpsc::UnboundedSender<Frame>,
    node_tx: mpsc::UnboundedSender<Frame>,
}

#[derive(Clone)]
pub struct ControlServer {
    config: Arc<ControlConfig>,
    nodes: Arc<RwLock<HashMap<String, ActiveNode>>>,
    domain_to_node: Arc<RwLock<HashMap<String, String>>>,
    clients: Arc<RwLock<HashMap<String, ActiveClient>>>,
    ip_counter: Arc<RwLock<u8>>,
    active_streams: Arc<RwLock<HashMap<u64, StreamPair>>>,
    acl: Arc<AclEngine>,
    pub token_mgr: Arc<TokenManager>,
}

impl ControlServer {
    pub fn new(config: ControlConfig) -> Self {
        let rules = config.acls.clone().unwrap_or_default();
        Self {
            config: Arc::new(config),
            nodes: Arc::new(RwLock::new(HashMap::new())),
            domain_to_node: Arc::new(RwLock::new(HashMap::new())),
            clients: Arc::new(RwLock::new(HashMap::new())),
            ip_counter: Arc::new(RwLock::new(2)),
            active_streams: Arc::new(RwLock::new(HashMap::new())),
            acl: Arc::new(AclEngine::new(rules)),
            token_mgr: Arc::new(TokenManager::new()),
        }
    }

    pub async fn run(&self) -> Result<()> {
        let addr: SocketAddr = self.config.bind_addr.parse()?;
        let listener = TcpListener::bind(addr).await?;
        println!("Veil control plane active on {}", addr);

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let server = self.clone();
            tokio::spawn(async move {
                let _ = server.handle_peer(stream, peer_addr).await;
            });
        }
    }

    async fn handle_peer(&self, mut stream: TcpStream, _peer: SocketAddr) -> Result<()> {
        let codec = ObfuscatedCodec::new(self.config.network_secret.as_bytes());
        let mut read_buf = BytesMut::with_capacity(65536);
        let (tx, mut rx) = mpsc::unbounded_channel::<Frame>();

        let mut peer_role: Option<String> = None;

        loop {
            tokio::select! {
                res = stream.read_buf(&mut read_buf) => {
                    let n = res?;
                    if n == 0 {
                        break;
                    }
                    while let Some(frame) = codec.try_decode_frame(&mut read_buf)? {
                        self.process_frame(frame, &tx, &mut peer_role).await?;
                    }
                }
                Some(outgoing) = rx.recv() => {
                    let encoded = codec.encode_frame(&outgoing)?;
                    stream.write_all(&encoded).await?;
                }
            }
        }

        if let Some(id) = peer_role {
            self.remove_peer(&id).await;
        }
        Ok(())
    }

    async fn process_frame(
        &self,
        frame: Frame,
        peer_tx: &mpsc::UnboundedSender<Frame>,
        peer_role: &mut Option<String>,
    ) -> Result<()> {
        match frame {
            Frame::TokenEnroll {
                token,
                device_id,
                public_key,
                role: _,
            } => {
                match self.token_mgr.enroll_device(&token, device_id.clone(), public_key).await {
                    Ok(DeviceStatus::Approved) => {
                        let _ = peer_tx.send(Frame::EnrollResult {
                            status: "approved".to_string(),
                            message: "Device approved".to_string(),
                        });
                    }
                    Ok(DeviceStatus::Pending) => {
                        let _ = peer_tx.send(Frame::EnrollResult {
                            status: "pending".to_string(),
                            message: "Device enrolled but pending admin approval".to_string(),
                        });
                    }
                    Ok(DeviceStatus::Revoked) => {
                        let _ = peer_tx.send(Frame::EnrollResult {
                            status: "revoked".to_string(),
                            message: "Device enrollment revoked".to_string(),
                        });
                    }
                    Err(e) => {
                        let _ = peer_tx.send(Frame::EnrollResult {
                            status: "error".to_string(),
                            message: e.to_string(),
                        });
                    }
                }
            }

            Frame::RegisterNode {
                node_id,
                secret_token,
                domains,
                virtual_ip,
            } => {
                let valid_secret = secret_token == self.config.network_secret;
                let approved_token = self.token_mgr.is_approved(&node_id).await;

                if !valid_secret && !approved_token {
                    let _ = peer_tx.send(Frame::RegisterAck {
                        node_id: node_id.clone(),
                        virtual_ip: String::new(),
                        success: false,
                        message: "Unauthorized or unapproved node".to_string(),
                    });
                    return Err(anyhow!("Unauthorized node"));
                }

                let assigned_ip = if let Some(ip) = virtual_ip {
                    ip
                } else {
                    let mut cnt = self.ip_counter.write().await;
                    let ip = format!("10.42.0.{}", *cnt);
                    *cnt = cnt.saturating_add(1);
                    ip
                };

                {
                    let mut node_map = self.nodes.write().await;
                    let mut domain_map = self.domain_to_node.write().await;

                    for dom in &domains {
                        domain_map.insert(dom.to_lowercase(), node_id.clone());
                    }

                    node_map.insert(
                        node_id.clone(),
                        ActiveNode {
                            node_id: node_id.clone(),
                            virtual_ip: assigned_ip.clone(),
                            domains: domains.clone(),
                            sender: peer_tx.clone(),
                        },
                    );
                }

                *peer_role = Some(format!("node:{}", node_id));
                println!("Node connected: {} [{}] with domains: {:?}", node_id, assigned_ip, domains);

                let _ = peer_tx.send(Frame::RegisterAck {
                    node_id,
                    virtual_ip: assigned_ip,
                    success: true,
                    message: "Welcome to Veil".to_string(),
                });

                self.broadcast_domains().await;
            }

            Frame::RegisterClient {
                client_id,
                secret_token,
            } => {
                let valid_secret = secret_token == self.config.network_secret;
                let approved_token = self.token_mgr.is_approved(&client_id).await;

                if !valid_secret && !approved_token {
                    return Err(anyhow!("Unauthorized client"));
                }

                {
                    let mut client_map = self.clients.write().await;
                    client_map.insert(
                        client_id.clone(),
                        ActiveClient {
                            _client_id: client_id.clone(),
                            sender: peer_tx.clone(),
                        },
                    );
                }

                *peer_role = Some(format!("client:{}", client_id));
                println!("Client connected: {}", client_id);

                let routes = self.get_current_routes().await;
                let _ = peer_tx.send(Frame::DomainSync { routes });
            }

            Frame::DynamicRouteAdd { domain, .. } => {
                if let Some(role) = peer_role.as_deref() {
                    if let Some(node_id) = role.strip_prefix("node:") {
                        let mut dmap = self.domain_to_node.write().await;
                        let mut nmap = self.nodes.write().await;

                        dmap.insert(domain.to_lowercase(), node_id.to_string());
                        if let Some(node) = nmap.get_mut(node_id) {
                            if !node.domains.contains(&domain) {
                                node.domains.push(domain.clone());
                            }
                        }

                        println!("Dynamic route registered: {} -> {}", domain, node_id);
                        drop(dmap);
                        drop(nmap);
                        self.broadcast_domains().await;
                    }
                }
            }

            Frame::DynamicRouteRemove { domain } => {
                if let Some(role) = peer_role.as_deref() {
                    if let Some(node_id) = role.strip_prefix("node:") {
                        let mut dmap = self.domain_to_node.write().await;
                        let mut nmap = self.nodes.write().await;

                        dmap.remove(&domain.to_lowercase());
                        if let Some(node) = nmap.get_mut(node_id) {
                            node.domains.retain(|d| d != &domain);
                        }

                        println!("Dynamic route removed: {}", domain);
                        drop(dmap);
                        drop(nmap);
                        self.broadcast_domains().await;
                    }
                }
            }

            Frame::StreamOpen {
                stream_id,
                domain,
                target_port,
            } => {
                let client_id = peer_role
                    .as_deref()
                    .and_then(|r| r.strip_prefix("client:"))
                    .unwrap_or("unknown");

                if !self.acl.is_allowed(client_id, &domain) {
                    println!("ACL Denied: client '{}' -> domain '{}'", client_id, domain);
                    let _ = peer_tx.send(Frame::AclDenied {
                        domain,
                        reason: "Access forbidden by Veil ACL policy".to_string(),
                    });
                    return Ok(());
                }

                let target_node_id = {
                    let dmap = self.domain_to_node.read().await;
                    dmap.get(&domain.to_lowercase()).cloned()
                };

                if let Some(nid) = target_node_id {
                    let nmap = self.nodes.read().await;
                    if let Some(target_node) = nmap.get(&nid) {
                        let mut streams = self.active_streams.write().await;
                        streams.insert(
                            stream_id,
                            StreamPair {
                                client_tx: peer_tx.clone(),
                                node_tx: target_node.sender.clone(),
                            },
                        );

                        let _ = target_node.sender.send(Frame::StreamOpen {
                            stream_id,
                            domain,
                            target_port,
                        });
                    }
                }
            }

            Frame::StreamData { stream_id, payload } => {
                let streams = self.active_streams.read().await;
                if let Some(pair) = streams.get(&stream_id) {
                    if peer_tx.same_channel(&pair.client_tx) {
                        let _ = pair.node_tx.send(Frame::StreamData { stream_id, payload });
                    } else {
                        let _ = pair.client_tx.send(Frame::StreamData { stream_id, payload });
                    }
                }
            }

            Frame::StreamClose { stream_id } => {
                let mut streams = self.active_streams.write().await;
                if let Some(pair) = streams.remove(&stream_id) {
                    if peer_tx.same_channel(&pair.client_tx) {
                        let _ = pair.node_tx.send(Frame::StreamClose { stream_id });
                    } else {
                        let _ = pair.client_tx.send(Frame::StreamClose { stream_id });
                    }
                }
            }

            Frame::P2PCandidates {
                peer_id,
                candidates,
                probe_token,
            } => {
                let nmap = self.nodes.read().await;
                let cmap = self.clients.read().await;

                if let Some(target_node) = nmap.get(&peer_id) {
                    let _ = target_node.sender.send(Frame::P2PCandidates {
                        peer_id: peer_role.clone().unwrap_or_default(),
                        candidates,
                        probe_token,
                    });
                } else if let Some(target_client) = cmap.get(&peer_id) {
                    let _ = target_client.sender.send(Frame::P2PCandidates {
                        peer_id: peer_role.clone().unwrap_or_default(),
                        candidates,
                        probe_token,
                    });
                }
            }

            Frame::Heartbeat => {
                let _ = peer_tx.send(Frame::Heartbeat);
            }

            _ => {}
        }
        Ok(())
    }

    async fn get_current_routes(&self) -> Vec<RouteEntry> {
        let nmap = self.nodes.read().await;
        let mut routes = Vec::new();
        for node in nmap.values() {
            for dom in &node.domains {
                routes.push(RouteEntry {
                    domain: dom.clone(),
                    node_id: node.node_id.clone(),
                    virtual_ip: node.virtual_ip.clone(),
                    target_port: 80,
                });
            }
        }
        routes
    }

    async fn broadcast_domains(&self) {
        let routes = self.get_current_routes().await;
        let sync_frame = Frame::DomainSync { routes };
        let cmap = self.clients.read().await;
        for client in cmap.values() {
            let _ = client.sender.send(sync_frame.clone());
        }
    }

    async fn remove_peer(&self, peer_role: &str) {
        if let Some(node_id) = peer_role.strip_prefix("node:") {
            let mut nmap = self.nodes.write().await;
            let mut dmap = self.domain_to_node.write().await;
            if let Some(node) = nmap.remove(node_id) {
                for dom in &node.domains {
                    dmap.remove(&dom.to_lowercase());
                }
                println!("Node disconnected: {}", node_id);
            }
            drop(nmap);
            drop(dmap);
            self.broadcast_domains().await;
        } else if let Some(client_id) = peer_role.strip_prefix("client:") {
            let mut cmap = self.clients.write().await;
            cmap.remove(client_id);
            println!("Client disconnected: {}", client_id);
        }
    }
}
