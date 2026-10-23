use anyhow::{anyhow, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngExt;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

pub struct UdpDataPlane {
    socket: Arc<UdpSocket>,
    cipher: Arc<ChaCha20Poly1305>,
    peer_map: Arc<RwLock<HashMap<String, SocketAddr>>>,
}

impl UdpDataPlane {
    pub async fn bind(bind_addr: &str, network_secret: &[u8]) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await?;
        let key_bytes = blake3::hash(network_secret);
        let key = Key::from(*key_bytes.as_bytes());
        let cipher = ChaCha20Poly1305::new(&key);

        Ok(Self {
            socket: Arc::new(socket),
            cipher: Arc::new(cipher),
            peer_map: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn add_peer(&self, virtual_ip: String, endpoint: SocketAddr) {
        let mut map = self.peer_map.write().await;
        map.insert(virtual_ip, endpoint);
    }

    pub async fn send_ip_packet(&self, dst_virtual_ip: &str, raw_packet: &[u8]) -> Result<bool> {
        let endpoint = {
            let map = self.peer_map.read().await;
            match map.get(dst_virtual_ip) {
                Some(ep) => *ep,
                None => return Ok(false),
            }
        };

        let mut nonce_bytes = [0u8; 12];
        let mut rng = rand::rng();
        rng.fill(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        let ciphertext = self.cipher.encrypt(&nonce, raw_packet)
            .map_err(|e| anyhow!("Encryption error: {:?}", e))?;

        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);

        self.socket.send_to(&out, endpoint).await?;
        Ok(true)
    }

    pub async fn recv_ip_packet(&self) -> Result<(Vec<u8>, SocketAddr)> {
        let mut buf = [0u8; 65535];
        let (n, peer) = self.socket.recv_from(&mut buf).await?;
        if n < 12 {
            return Err(anyhow!("Packet too short"));
        }

        let nonce_arr: [u8; 12] = buf[..12].try_into()?;
        let nonce = Nonce::from(nonce_arr);
        let ciphertext = &buf[12..n];

        let plaintext = self.cipher.decrypt(&nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption error: {:?}", e))?;

        Ok((plaintext, peer))
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }
}
