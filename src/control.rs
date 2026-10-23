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
    exit_node: Arc<RwLock<Option<String>>>,
    active_pings: Arc<RwLock<HashMap<(String, u64), mpsc::UnboundedSender<Frame>>>>,
    pub kv_store: Arc<crate::kv::KvStore>,
    active_execs: Arc<RwLock<HashMap<String, mpsc::UnboundedSender<Frame>>>>,
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
            exit_node: Arc::new(RwLock::new(None)),
            active_pings: Arc::new(RwLock::new(HashMap::new())),
            kv_store: Arc::new(crate::kv::KvStore::new()),
            active_execs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn run(&self) -> Result<()> {
        let addr: SocketAddr = self.config.bind_addr.parse()?;
        let listener = TcpListener::bind(addr).await?;
        println!("Veil control plane active on {}", addr);

        let web_addr = self.config.web_addr.clone().unwrap_or_else(|| "0.0.0.0:9090".to_string());
        let control_addr = self.config.bind_addr.clone();
        let secret = self.config.network_secret.clone();
        tokio::spawn(async move {
            let dash = crate::dashboard::DashboardServer::new(web_addr, control_addr, secret);
            let _ = dash.run().await;
        });

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
        let mut first_packet = true;

        loop {
            tokio::select! {
                res = stream.read_buf(&mut read_buf) => {
                    let n = res?;
                    if n == 0 {
                        break;
                    }
                    if first_packet {
                        first_packet = false;
                        match codec.try_decode_frame(&mut read_buf) {
                            Ok(Some(frame)) => {
                                self.process_frame(frame, &tx, &mut peer_role).await?;
                                while let Some(next) = codec.try_decode_frame(&mut read_buf)? {
                                    self.process_frame(next, &tx, &mut peer_role).await?;
                                }
                            }
                            Ok(None) => {}
                            Err(_) => {
                                if let Some(decoy) = &self.config.decoy_addr {
                                    let proxy = crate::decoy::DecoyProxy::new(decoy.clone());
                                    let _ = proxy.forward(&read_buf, stream).await;
                                    return Ok(());
                                }
                                break;
                            }
                        }
                    } else {
                        while let Some(frame) = codec.try_decode_frame(&mut read_buf)? {
                            self.process_frame(frame, &tx, &mut peer_role).await?;
                        }
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

            Frame::SetExitNode { exit_node_id } => {
                let mut en = self.exit_node.write().await;
                *en = Some(exit_node_id.clone());
                println!("Veil exit node configured: {}", exit_node_id);
            }

            Frame::IpPacket { src_ip, dst_ip, payload } => {
                let nmap = self.nodes.read().await;
                let mut sent = false;
                for node in nmap.values() {
                    if node.virtual_ip == dst_ip {
                        let _ = node.sender.send(Frame::IpPacket {
                            src_ip: src_ip.clone(),
                            dst_ip: dst_ip.clone(),
                            payload: payload.clone(),
                        });
                        sent = true;
                        break;
                    }
                }
                if !sent {
                    let cmap = self.clients.read().await;
                    for client in cmap.values() {
                        let _ = client.sender.send(Frame::IpPacket {
                            src_ip: src_ip.clone(),
                            dst_ip: dst_ip.clone(),
                            payload: payload.clone(),
                        });
                        sent = true;
                        break;
                    }
                }
                if !sent {
                    let en = self.exit_node.read().await;
                    if let Some(target_exit) = en.as_ref() {
                        if let Some(node) = nmap.get(target_exit) {
                            let _ = node.sender.send(Frame::IpPacket {
                                src_ip,
                                dst_ip,
                                payload,
                            });
                        }
                    }
                }
            }

            Frame::PingRequest { target_node, seq, timestamp_ms } => {
                let nmap = self.nodes.read().await;
                if let Some(node) = nmap.get(&target_node) {
                    self.active_pings.write().await.insert((target_node.clone(), seq), peer_tx.clone());
                    let _ = node.sender.send(Frame::PingRequest {
                        target_node: target_node.clone(),
                        seq,
                        timestamp_ms,
                    });
                } else {
                    let _ = peer_tx.send(Frame::PingResponse {
                        from_node: target_node,
                        seq,
                        timestamp_ms,
                    });
                }
            }

            Frame::PingResponse { from_node, seq, timestamp_ms } => {
                let mut pings = self.active_pings.write().await;
                if let Some(sender) = pings.remove(&(from_node.clone(), seq)) {
                    let _ = sender.send(Frame::PingResponse {
                        from_node,
                        seq,
                        timestamp_ms,
                    });
                }
            }

            Frame::FileTransferInit { target_node, transfer_id, filename, target_path, total_size } => {
                let nmap = self.nodes.read().await;
                if let Some(node) = nmap.get(&target_node) {
                    let _ = node.sender.send(Frame::FileTransferInit {
                        transfer_id,
                        target_node,
                        filename,
                        target_path,
                        total_size,
                    });
                }
            }

            Frame::FileTransferChunk { target_node, transfer_id, offset, data } => {
                let nmap = self.nodes.read().await;
                if let Some(node) = nmap.get(&target_node) {
                    let _ = node.sender.send(Frame::FileTransferChunk {
                        transfer_id,
                        target_node,
                        offset,
                        data,
                    });
                }
            }

            Frame::FileTransferDone { target_node, transfer_id, success, message } => {
                let nmap = self.nodes.read().await;
                if let Some(node) = nmap.get(&target_node) {
                    let _ = node.sender.send(Frame::FileTransferDone {
                        transfer_id,
                        target_node,
                        success,
                        message,
                    });
                } else {
                    let cmap = self.clients.read().await;
                    for client in cmap.values() {
                        let _ = client.sender.send(Frame::FileTransferDone {
                            transfer_id: transfer_id.clone(),
                            target_node: target_node.clone(),
                            success,
                            message: message.clone(),
                        });
                    }
                }
            }

            Frame::NodeStatusQuery => {
                let nmap = self.nodes.read().await;
                let mut status_items = Vec::new();
                for node in nmap.values() {
                    status_items.push(crate::proto::NodeStatusItem {
                        node_id: node.node_id.clone(),
                        virtual_ip: node.virtual_ip.clone(),
                        domains: node.domains.clone(),
                        rx_bytes: 0,
                        tx_bytes: 0,
                        is_direct: true,
                        latency_ms: None,
                    });
                }
                let _ = peer_tx.send(Frame::NodeStatusReply { nodes: status_items });
            }

            Frame::ExecRequest { exec_id, target_node, command } => {
                self.active_execs.write().await.insert(exec_id.clone(), peer_tx.clone());
                let nmap = self.nodes.read().await;
                if let Some(node) = nmap.get(&target_node) {
                    let _ = node.sender.send(Frame::ExecRequest { exec_id, target_node, command });
                } else {
                    let _ = peer_tx.send(Frame::ExecResponse {
                        exec_id,
                        from_node: target_node,
                        exit_code: 1,
                        stdout: String::new(),
                        stderr: "Target node offline or not found".to_string(),
                    });
                }
            }

            Frame::ExecResponse { exec_id, from_node, exit_code, stdout, stderr } => {
                let mut execs = self.active_execs.write().await;
                if let Some(sender) = execs.remove(&exec_id) {
                    let _ = sender.send(Frame::ExecResponse {
                        exec_id,
                        from_node,
                        exit_code,
                        stdout,
                        stderr,
                    });
                }
            }

            Frame::KvSet { key, value } => {
                self.kv_store.set(&key, &value).await;
                let _ = peer_tx.send(Frame::KvReply { key, value: Some(value) });
            }

            Frame::KvGet { key } => {
                let val = self.kv_store.get(&key).await;
                let _ = peer_tx.send(Frame::KvReply { key, value: val });
            }

            Frame::KvList => {
                let entries = self.kv_store.list().await;
                let _ = peer_tx.send(Frame::KvListReply { entries });
            }

            Frame::LockdownNotice { initiator } => {
                let nmap = self.nodes.read().await;
                for node in nmap.values() {
                    let _ = node.sender.send(Frame::LockdownNotice { initiator: initiator.clone() });
                }
                let cmap = self.clients.read().await;
                for client in cmap.values() {
                    let _ = client.sender.send(Frame::LockdownNotice { initiator: initiator.clone() });
                }
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
