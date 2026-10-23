use anyhow::Result;
use rand::RngExt;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;

pub struct SpaAuth;

impl SpaAuth {
    pub fn create_knock_packet(network_secret: &[u8], client_id: &str) -> [u8; 64] {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut packet = [0u8; 64];
        packet[..8].copy_from_slice(&now.to_be_bytes());

        let mut rng = rand::rng();
        rng.fill(&mut packet[8..16]);

        let id_hash = blake3::hash(client_id.as_bytes());
        packet[16..32].copy_from_slice(&id_hash.as_bytes()[..16]);

        let hmac = blake3::keyed_hash(blake3::hash(network_secret).as_bytes(), &packet[..32]);
        packet[32..64].copy_from_slice(hmac.as_bytes());

        packet
    }

    pub fn verify_knock_packet(network_secret: &[u8], packet: &[u8], max_skew_seconds: u64) -> Result<bool> {
        if packet.len() != 64 {
            return Ok(false);
        }

        let timestamp = u64::from_be_bytes(packet[..8].try_into().unwrap());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let diff = if now > timestamp {
            now - timestamp
        } else {
            timestamp - now
        };

        if diff > max_skew_seconds {
            return Ok(false);
        }

        let expected_hmac = blake3::keyed_hash(blake3::hash(network_secret).as_bytes(), &packet[..32]);
        if &packet[32..64] != expected_hmac.as_bytes() {
            return Ok(false);
        }

        Ok(true)
    }

    pub async fn send_knock(endpoint: &str, network_secret: &[u8], client_id: &str) -> Result<()> {
        let packet = Self::create_knock_packet(network_secret, client_id);
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.send_to(&packet, endpoint).await?;
        Ok(())
    }
}
