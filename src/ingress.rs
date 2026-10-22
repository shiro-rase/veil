use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct IngressRouter {
    routes: Arc<RwLock<HashMap<String, String>>>,
}

impl IngressRouter {
    pub fn new(initial_routes: HashMap<String, String>) -> Self {
        let mut map = HashMap::new();
        for (dom, target) in initial_routes {
            map.insert(dom.to_lowercase(), target);
        }
        Self {
            routes: Arc::new(RwLock::new(map)),
        }
    }

    pub async fn add_route(&self, domain: String, target_addr: String) {
        let mut map = self.routes.write().await;
        map.insert(domain.to_lowercase(), target_addr);
    }

    pub async fn remove_route(&self, domain: &str) {
        let mut map = self.routes.write().await;
        map.remove(&domain.to_lowercase());
    }

    pub async fn list_routes(&self) -> Vec<(String, String)> {
        let map = self.routes.read().await;
        map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    pub async fn get_target(&self, host: &str) -> Option<String> {
        let clean_host = host.split(':').next()?.to_lowercase();
        let map = self.routes.read().await;
        map.get(&clean_host).cloned().or_else(|| {
            map.iter().find_map(|(pattern, target)| {
                if pattern.starts_with("*.") {
                    let suffix = &pattern[2..];
                    if clean_host.ends_with(suffix) {
                        return Some(target.clone());
                    }
                }
                None
            })
        })
    }

    pub async fn start(&self, bind_addr: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(bind_addr).await?;
        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => continue,
            };

            let router = self.clone();
            tokio::spawn(async move {
                let _ = router.handle_connection(stream, peer_addr).await;
            });
        }
    }

    async fn handle_connection(&self, mut client: TcpStream, _peer: SocketAddr) -> Result<()> {
        let mut peek_buf = vec![0u8; 4096];
        let n = client.peek(&mut peek_buf).await?;
        if n == 0 {
            return Ok(());
        }

        let host = if let Some(h) = Self::parse_http_host(&peek_buf[..n]) {
            h
        } else if let Some(sni) = Self::parse_tls_sni(&peek_buf[..n]) {
            sni
        } else {
            return Err(anyhow!("Unable to extract Host or SNI"));
        };

        let target_addr = self
            .get_target(&host)
            .await
            .ok_or_else(|| anyhow!("No route configured for host: {host}"))?;

        let mut backend = TcpStream::connect(&target_addr).await?;
        tokio::io::copy_bidirectional(&mut client, &mut backend).await?;
        Ok(())
    }

    pub fn parse_http_host(buf: &[u8]) -> Option<String> {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        if req.parse(buf).is_ok() {
            for h in req.headers {
                if h.name.eq_ignore_ascii_case("Host") {
                    let host_str = std::str::from_utf8(h.value).ok()?;
                    let clean = host_str.split(':').next()?.trim();
                    return Some(clean.to_string());
                }
            }
        }
        None
    }

    pub fn parse_tls_sni(buf: &[u8]) -> Option<String> {
        if buf.len() < 43 || buf[0] != 0x16 || buf[1] != 0x03 {
            return None;
        }

        let mut pos = 43;
        if pos >= buf.len() {
            return None;
        }
        let session_id_len = buf[pos] as usize;
        pos += 1 + session_id_len;

        if pos + 2 > buf.len() {
            return None;
        }
        let cipher_suites_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
        pos += 2 + cipher_suites_len;

        if pos + 1 > buf.len() {
            return None;
        }
        let compression_len = buf[pos] as usize;
        pos += 1 + compression_len;

        if pos + 2 > buf.len() {
            return None;
        }
        let extensions_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
        pos += 2;

        let end = (pos + extensions_len).min(buf.len());
        while pos + 4 <= end {
            let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            let ext_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
            pos += 4;

            if ext_type == 0 && pos + ext_len <= end {
                if pos + 5 > end {
                    return None;
                }
                let name_len = u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]) as usize;
                let name_start = pos + 5;
                if name_start + name_len <= end {
                    let sni = std::str::from_utf8(&buf[name_start..name_start + name_len]).ok()?;
                    return Some(sni.to_string());
                }
            }
            pos += ext_len;
        }
        None
    }
}
