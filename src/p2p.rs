use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::time::{sleep, Duration};

pub struct P2PPuncher {
    socket: Arc<UdpSocket>,
}

impl P2PPuncher {
    pub async fn bind(local_port: u16) -> Result<Self> {
        let sock = UdpSocket::bind(format!("0.0.0.0:{}", local_port)).await?;
        Ok(Self {
            socket: Arc::new(sock),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    pub async fn punch_hole(
        &self,
        candidates: &[SocketAddr],
        probe_token: &[u8; 16],
    ) -> Option<SocketAddr> {
        let sock = self.socket.clone();
        let token = *probe_token;
        let cands = candidates.to_vec();

        let sender_task = tokio::spawn(async move {
            let mut payload = Vec::with_capacity(20);
            payload.extend_from_slice(b"VEIL");
            payload.extend_from_slice(&token);

            for _ in 0..6 {
                for addr in &cands {
                    let _ = sock.send_to(&payload, *addr).await;
                }
                sleep(Duration::from_millis(50)).await;
            }
        });

        let mut buf = [0u8; 64];
        let timeout_fut = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Ok((len, src)) = self.socket.recv_from(&mut buf).await {
                    if len >= 20 && &buf[..4] == b"VEIL" && &buf[4..20] == probe_token {
                        let _ = self.socket.send_to(b"VEIL_OK", src).await;
                        return Some(src);
                    }
                }
            }
        });

        let res = match timeout_fut.await {
            Ok(found) => found,
            Err(_) => None,
        };

        let _ = sender_task.await;
        res
    }
}
