use crate::config::ClientConfig;
use crate::dns::DnsResolver;
use crate::ingress::IngressRouter;
use crate::proto::{Frame, ObfuscatedCodec};
use crate::tun::TunDevice;
use anyhow::{anyhow, Result};
use bytes::BytesMut;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tokio::time::{sleep, Duration};

static STREAM_COUNTER: AtomicU64 = AtomicU64::new(1);

pub struct ClientAgent {
    config: Arc<ClientConfig>,
    dns: DnsResolver,
    active_streams: Arc<RwLock<HashMap<u64, mpsc::UnboundedSender<Vec<u8>>>>>,
    to_control_tx: Arc<RwLock<Option<mpsc::UnboundedSender<Frame>>>>,
    tun_tx: Arc<RwLock<Option<mpsc::UnboundedSender<Vec<u8>>>>>,
}

impl ClientAgent {
    pub fn new(config: ClientConfig) -> Result<Self> {
        let upstream: SocketAddr = config.upstream_dns.parse()?;
        let dns = DnsResolver::new(upstream);
        Ok(Self {
            config: Arc::new(config),
            dns,
            active_streams: Arc::new(RwLock::new(HashMap::new())),
            to_control_tx: Arc::new(RwLock::new(None)),
            tun_tx: Arc::new(RwLock::new(None)),
        })
    }

    pub async fn run(&self) -> Result<()> {
        let dns = self.dns.clone();
        let dns_bind: SocketAddr = self.config.dns_bind.parse()?;
        tokio::spawn(async move {
            println!("Veil internal DNS active on {}", dns_bind);
            let _ = dns.start(dns_bind).await;
        });

        let local_http_addr: SocketAddr = self.config.local_http_bind.parse()?;
        let client_ref = Arc::new(self.clone_state());
        tokio::spawn(async move {
            println!("Veil local HTTP interceptor listening on {}", local_http_addr);
            let _ = client_ref.start_http_interceptor(local_http_addr).await;
        });

        if let Some(socks_addr) = &self.config.socks5_bind {
            if let Ok(addr) = socks_addr.parse() {
                let s5 = crate::socks5::Socks5Server::new(
                    addr,
                    self.to_control_tx.clone(),
                    self.active_streams.clone(),
                );
                tokio::spawn(async move {
                    let _ = s5.start().await;
                });
            }
        }

        loop {
            match self.connect_control_loop().await {
                Ok(_) => {
                    println!("Client disconnected cleanly, reconnecting in 2s...");
                }
                Err(e) => {
                    eprintln!("Control connection error: {e}, retrying in 3s...");
                }
            }
            sleep(Duration::from_secs(3)).await;
        }
    }

    fn clone_state(&self) -> Self {
        Self {
            config: self.config.clone(),
            dns: self.dns.clone(),
            active_streams: self.active_streams.clone(),
            to_control_tx: self.to_control_tx.clone(),
            tun_tx: self.tun_tx.clone(),
        }
    }

    async fn connect_control_loop(&self) -> Result<()> {
        let stream = TcpStream::connect(&self.config.control_server).await?;
        println!("Connected to Veil control plane at {}", self.config.control_server);

        let (mut reader, mut writer) = stream.into_split();
        let codec = Arc::new(ObfuscatedCodec::new(self.config.network_secret.as_bytes()));
        let (tx, mut rx) = mpsc::unbounded_channel::<Frame>();

        *self.to_control_tx.write().await = Some(tx.clone());

        let reg = Frame::RegisterClient {
            client_id: self.config.client_id.clone(),
            secret_token: self.config.network_secret.clone(),
        };

        let encoded = codec.encode_frame(&reg)?;
        writer.write_all(&encoded).await?;

        if let Some(ref exit_node) = self.config.exit_node {
            let _ = tx.send(Frame::SetExitNode {
                exit_node_id: exit_node.clone(),
            });
            println!("Requesting exit node route via: {}", exit_node);
        }

        if self.config.tun_enabled.unwrap_or(true) {
            match TunDevice::create("veil0", Ipv4Addr::new(10, 42, 0, 100)) {
                Ok(mut tun) => {
                    println!("Virtual interface veil0 active with IP 10.42.0.100");
                    if self.config.exit_node.is_some() {
                        let _ = TunDevice::setup_exit_node_routes(&self.config.control_server, "veil0");
                        println!("Exit node default routing enabled via veil0");
                    }

                    let (t_in_tx, mut t_in_rx) = mpsc::unbounded_channel::<Vec<u8>>();
                    *self.tun_tx.write().await = Some(t_in_tx);

                    let to_ctrl_packet = tx.clone();
                    tokio::spawn(async move {
                        let mut buf = [0u8; 4096];
                        loop {
                            tokio::select! {
                                read_res = tun.read_packet(&mut buf) => {
                                    if let Ok(n) = read_res {
                                        if n >= 20 {
                                            let dst = format!("{}.{}.{}.{}", buf[16], buf[17], buf[18], buf[19]);
                                            let _ = to_ctrl_packet.send(Frame::IpPacket {
                                                src_ip: "10.42.0.100".to_string(),
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
                self.handle_frame(frame).await?;
            }
        }
    }

    async fn handle_frame(&self, frame: Frame) -> Result<()> {
        match frame {
            Frame::DomainSync { routes } => {
                let mut map = HashMap::new();
                for r in &routes {
                    map.insert(r.domain.clone(), Ipv4Addr::new(127, 0, 0, 1));
                    println!("Synced Veil domain: {} -> {}", r.domain, r.virtual_ip);
                }
                self.dns.update_domains(map).await;
                let _ = TunDevice::sync_hosts(&routes);
            }

            Frame::IpPacket { payload, .. } => {
                let lock = self.tun_tx.read().await;
                if let Some(ref tx) = *lock {
                    let _ = tx.send(payload);
                }
            }

            Frame::StreamData { stream_id, payload } => {
                let streams = self.active_streams.read().await;
                if let Some(target) = streams.get(&stream_id) {
                    let _ = target.send(payload);
                }
            }

            Frame::StreamClose { stream_id } => {
                self.active_streams.write().await.remove(&stream_id);
            }

            Frame::PingResponse { from_node, seq, timestamp_ms } => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                let rtt = now.saturating_sub(timestamp_ms);
                println!("Ping reply from {}: seq={} rtt={}ms", from_node, seq, rtt);
            }

            Frame::Heartbeat => {}
            _ => {}
        }
        Ok(())
    }

    async fn start_http_interceptor(&self, addr: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(c) => c,
                Err(_) => continue,
            };

            let streams_map = self.active_streams.clone();
            let ctrl_tx_lock = self.to_control_tx.clone();

            tokio::spawn(async move {
                let _ = Self::handle_local_client(stream, streams_map, ctrl_tx_lock).await;
            });
        }
    }

    async fn handle_local_client(
        stream: TcpStream,
        active_streams: Arc<RwLock<HashMap<u64, mpsc::UnboundedSender<Vec<u8>>>>>,
        to_control_tx: Arc<RwLock<Option<mpsc::UnboundedSender<Frame>>>>,
    ) -> Result<()> {
        let mut peek_buf = vec![0u8; 4096];
        let n = stream.peek(&mut peek_buf).await?;
        if n == 0 {
            return Ok(());
        }

        let req_str = String::from_utf8_lossy(&peek_buf[..n]);
        let first_line = req_str.lines().next().unwrap_or("");
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() >= 2 {
            let path = parts[1];
            if path == "/proxy.pac" || path == "/veil.pac" {
                let pac = "function FindProxyForURL(url, host) {\n  if (shExpMatch(host, \"*.vps\") || shExpMatch(host, \"*.mesh\") || host === \"hui.hui.hui\") {\n    return \"SOCKS5 127.0.0.1:1080; SOCKS 127.0.0.1:1080\";\n  }\n  return \"DIRECT\";\n}\n";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    pac.len(),
                    pac
                );
                let mut s = stream;
                let _ = s.write_all(resp.as_bytes()).await;
                return Ok(());
            }
            if path == "/veil-ca.crt" || path == "/ca.crt" {
                let ca_path = std::path::Path::new("/home/user/.config/veil/certs/veil-ca.crt");
                if let Ok(ca_bytes) = std::fs::read(ca_path) {
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/x-x509-ca-cert\r\nContent-Disposition: attachment; filename=\"veil-ca.crt\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        ca_bytes.len()
                    );
                    let mut s = stream;
                    let _ = s.write_all(resp.as_bytes()).await;
                    let _ = s.write_all(&ca_bytes).await;
                    return Ok(());
                }
            }
        }

        let host = if let Some(h) = IngressRouter::parse_http_host(&peek_buf[..n]) {
            h
        } else if let Some(sni) = IngressRouter::parse_tls_sni(&peek_buf[..n]) {
            sni
        } else {
            return Err(anyhow!("No Host or SNI header found"));
        };

        if (host.starts_with("127.0.0.1") || host.starts_with("localhost")) && parts.len() >= 2 && parts[1] == "/" {
            let page = "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\"><title>Veil Client Proxy</title><style>:root{--bg:#0a0e14;--card:#111722;--accent:#38bdf8;--green:#00e676;--text:#f1f5f9;--sub:#94a3b8;--border:#1e293b;}body{background:var(--bg);color:var(--text);font-family:ui-monospace,monospace;padding:32px;display:flex;justify-content:center;}main{max-width:640px;width:100%;}.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:24px;margin-bottom:16px;}h1{font-size:18px;margin-bottom:12px;color:var(--accent);}p{color:var(--sub);font-size:13px;line-height:1.6;margin-bottom:8px;}a{color:var(--accent);text-decoration:none;}.link-pill{display:inline-block;background:#172030;border:1px solid var(--border);padding:6px 12px;border-radius:4px;margin:4px 4px 4px 0;font-size:12px;}</style></head><body><main><div class=\"card\"><h1>VEIL CLIENT OVERLAY</h1><p>SOCKS5 Proxy: <strong>127.0.0.1:1080</strong></p><p>Automatic PAC Script: <a href=\"/proxy.pac\">http://127.0.0.1:8880/proxy.pac</a></p><p>Root Certificate: <a href=\"/veil-ca.crt\">Download veil-ca.crt</a></p></div><div class=\"card\"><h1>NODE CONSOLES</h1><div><a class=\"link-pill\" href=\"https://arch.vps\">https://arch.vps</a><a class=\"link-pill\" href=\"https://fedora.vps\">https://fedora.vps</a><a class=\"link-pill\" href=\"https://local.vps\">https://local.vps</a></div></div></main></body></html>";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                page.len(),
                page
            );
            let mut s = stream;
            let _ = s.write_all(resp.as_bytes()).await;
            return Ok(());
        }

        let stream_id = STREAM_COUNTER.fetch_add(1, Ordering::SeqCst);
        let ctrl_tx = {
            let lock = to_control_tx.read().await;
            lock.clone().ok_or_else(|| anyhow!("Not connected to control plane"))?
        };

        let (mut s_read, mut s_write) = stream.into_split();
        let (tx_to_browser, mut rx_to_browser) = mpsc::unbounded_channel::<Vec<u8>>();

        active_streams.write().await.insert(stream_id, tx_to_browser);

        ctrl_tx.send(Frame::StreamOpen {
            stream_id,
            domain: host,
            target_port: 80,
        })?;

        tokio::spawn(async move {
            while let Some(chunk) = rx_to_browser.recv().await {
                if s_write.write_all(&chunk).await.is_err() {
                    break;
                }
            }
            let _ = s_write.shutdown().await;
        });

        let ctrl_tx_cleanup = ctrl_tx.clone();
        let streams_cleanup = active_streams.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 8192];
            loop {
                match s_read.read(&mut buf).await {
                    Ok(n) if n > 0 => {
                        let _ = ctrl_tx_cleanup.send(Frame::StreamData {
                            stream_id,
                            payload: buf[..n].to_vec(),
                        });
                    }
                    _ => break,
                }
            }
            let _ = ctrl_tx_cleanup.send(Frame::StreamClose { stream_id });
            streams_cleanup.write().await.remove(&stream_id);
        });

        Ok(())
    }
}
