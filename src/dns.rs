use anyhow::Result;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct DnsResolver {
    records: Arc<RwLock<HashMap<String, Ipv4Addr>>>,
    upstream: SocketAddr,
}

impl DnsResolver {
    pub fn new(upstream: SocketAddr) -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
            upstream,
        }
    }

    pub async fn set_domain(&self, domain: String, ip: Ipv4Addr) {
        let mut map = self.records.write().await;
        map.insert(domain.to_lowercase(), ip);
    }

    pub async fn update_domains(&self, routes: HashMap<String, Ipv4Addr>) {
        let mut map = self.records.write().await;
        for (dom, ip) in routes {
            map.insert(dom.to_lowercase(), ip);
        }
    }

    pub async fn start(&self, bind_addr: SocketAddr) -> Result<()> {
        let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
        let mut buf = [0u8; 1024];

        loop {
            let (len, src) = match socket.recv_from(&mut buf).await {
                Ok(res) => res,
                Err(_) => continue,
            };

            let query_bytes = buf[..len].to_vec();
            let resolver = self.clone();
            let sock = socket.clone();

            tokio::spawn(async move {
                if let Some(resp) = resolver.handle_query(&query_bytes).await {
                    let _ = sock.send_to(&resp, src).await;
                }
            });
        }
    }

    pub async fn handle_query(&self, query: &[u8]) -> Option<Vec<u8>> {
        if query.len() < 12 {
            return None;
        }

        let qname = Self::extract_qname(query, 12)?;
        let qname_lower = qname.to_lowercase();

        let matched_ip = {
            let map = self.records.read().await;
            map.get(&qname_lower).copied().or_else(|| {
                map.iter().find_map(|(pattern, ip)| {
                    if pattern.starts_with("*.") {
                        let suffix = &pattern[2..];
                        if qname_lower.ends_with(suffix) {
                            return Some(*ip);
                        }
                    }
                    None
                })
            })
        };

        if let Some(ip) = matched_ip {
            Some(Self::build_a_response(query, ip))
        } else {
            self.forward_upstream(query).await
        }
    }

    async fn forward_upstream(&self, query: &[u8]) -> Option<Vec<u8>> {
        let upstream_sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
        upstream_sock.connect(self.upstream).await.ok()?;
        upstream_sock.send(query).await.ok()?;

        let mut resp_buf = [0u8; 1024];
        let Ok(len) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            upstream_sock.recv(&mut resp_buf),
        )
        .await
        else {
            return None;
        };

        len.ok().map(|l| resp_buf[..l].to_vec())
    }

    fn extract_qname(buf: &[u8], mut offset: usize) -> Option<String> {
        let mut labels = Vec::new();
        while offset < buf.len() {
            let len = buf[offset] as usize;
            if len == 0 {
                break;
            }
            offset += 1;
            if offset + len > buf.len() {
                return None;
            }
            let label = std::str::from_utf8(&buf[offset..offset + len]).ok()?;
            labels.push(label);
            offset += len;
        }
        if labels.is_empty() {
            None
        } else {
            Some(labels.join("."))
        }
    }

    fn build_a_response(query: &[u8], ip: Ipv4Addr) -> Vec<u8> {
        let mut resp = Vec::with_capacity(query.len() + 16);
        resp.extend_from_slice(&query[..2]);
        resp.extend_from_slice(&[0x81, 0x80]);
        resp.extend_from_slice(&query[4..6]);
        resp.extend_from_slice(&[0x00, 0x01]);
        resp.extend_from_slice(&[0x00, 0x00]);
        resp.extend_from_slice(&[0x00, 0x00]);

        let mut q_end = 12;
        while q_end < query.len() && query[q_end] != 0 {
            q_end += 1 + query[q_end] as usize;
        }
        q_end = (q_end + 5).min(query.len());
        resp.extend_from_slice(&query[12..q_end]);

        resp.extend_from_slice(&[0xc0, 0x0c]);
        resp.extend_from_slice(&[0x00, 0x01]);
        resp.extend_from_slice(&[0x00, 0x01]);
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]);
        resp.extend_from_slice(&[0x00, 0x04]);
        resp.extend_from_slice(&ip.octets());
        resp
    }
}
