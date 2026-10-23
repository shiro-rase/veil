use anyhow::{anyhow, Result};
use bytes::{Buf, BufMut, BytesMut};
use rand::RngExt;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Frame {
    HandshakeInit {
        ephemeral_public: [u8; 32],
        timestamp: u64,
    },
    HandshakeResp {
        ephemeral_public: [u8; 32],
    },
    RegisterNode {
        node_id: String,
        secret_token: String,
        domains: Vec<String>,
        virtual_ip: Option<String>,
    },
    RegisterAck {
        node_id: String,
        virtual_ip: String,
        success: bool,
        message: String,
    },
    RegisterClient {
        client_id: String,
        secret_token: String,
    },
    DomainSync {
        routes: Vec<RouteEntry>,
    },
    StreamOpen {
        stream_id: u64,
        domain: String,
        target_port: u16,
    },
    StreamData {
        stream_id: u64,
        payload: Vec<u8>,
    },
    StreamClose {
        stream_id: u64,
    },
    Heartbeat,
    TokenEnroll {
        token: String,
        device_id: String,
        public_key: String,
        role: String,
    },
    EnrollResult {
        status: String,
        message: String,
    },
    P2PCandidates {
        peer_id: String,
        candidates: Vec<String>,
        probe_token: [u8; 16],
    },
    DynamicRouteAdd {
        domain: String,
        target_port: u16,
    },
    DynamicRouteRemove {
        domain: String,
    },
    AclDenied {
        domain: String,
        reason: String,
    },
    IpPacket {
        src_ip: String,
        dst_ip: String,
        payload: Vec<u8>,
    },
    PingRequest {
        target_node: String,
        seq: u64,
        timestamp_ms: u64,
    },
    PingResponse {
        from_node: String,
        seq: u64,
        timestamp_ms: u64,
    },
    FileTransferInit {
        transfer_id: String,
        target_node: String,
        filename: String,
        target_path: String,
        total_size: u64,
    },
    FileTransferChunk {
        transfer_id: String,
        target_node: String,
        offset: u64,
        data: Vec<u8>,
    },
    FileTransferDone {
        transfer_id: String,
        target_node: String,
        success: bool,
        message: String,
    },
    NodeStatusQuery,
    NodeStatusReply {
        nodes: Vec<NodeStatusItem>,
    },
    SetExitNode {
        exit_node_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatusItem {
    pub node_id: String,
    pub virtual_ip: String,
    pub domains: Vec<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub is_direct: bool,
    pub latency_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteEntry {
    pub domain: String,
    pub node_id: String,
    pub virtual_ip: String,
    pub target_port: u16,
}

pub struct ObfuscatedCodec {
    mask_key: [u8; 32],
}

impl ObfuscatedCodec {
    pub fn new(network_secret: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(network_secret);
        hasher.update(b"veil-v1-obfuscation-mask");
        Self {
            mask_key: *hasher.finalize().as_bytes(),
        }
    }

    pub fn encode_frame(&self, frame: &Frame) -> Result<Vec<u8>> {
        let serialized = serde_json::to_vec(frame)?;
        let mut rng = rand::rng();
        let pad_len = rng.random_range(16..=48);
        let mut padding = vec![0u8; pad_len];
        rng.fill(&mut padding[..]);

        let payload_len = serialized.len() as u32;
        let mut raw = Vec::with_capacity(4 + 1 + serialized.len() + pad_len);
        raw.put_u32(payload_len);
        raw.put_u8(pad_len as u8);
        raw.extend_from_slice(&serialized);
        raw.extend_from_slice(&padding);

        self.apply_mask(&mut raw);
        let total_len = raw.len() as u32;
        let mut packet = Vec::with_capacity(4 + raw.len());
        packet.put_u32(total_len ^ u32::from_be_bytes(self.mask_key[..4].try_into().unwrap()));
        packet.extend_from_slice(&raw);
        Ok(packet)
    }

    pub fn try_decode_frame(&self, buf: &mut BytesMut) -> Result<Option<Frame>> {
        if buf.len() < 4 {
            return Ok(None);
        }
        let header_mask = u32::from_be_bytes(self.mask_key[..4].try_into().unwrap());
        let masked_len = u32::from_be_bytes(buf[..4].try_into().unwrap());
        let total_len = (masked_len ^ header_mask) as usize;

        if total_len > 16 * 1024 * 1024 {
            return Err(anyhow!("Frame exceeds max size limit"));
        }
        if buf.len() < 4 + total_len {
            return Ok(None);
        }

        buf.advance(4);
        let mut raw = buf.split_to(total_len).to_vec();
        self.apply_mask(&mut raw);

        if raw.len() < 5 {
            return Err(anyhow!("Corrupted frame data"));
        }
        let payload_len = u32::from_be_bytes(raw[..4].try_into().unwrap()) as usize;
        let pad_len = raw[4] as usize;

        if 5 + payload_len + pad_len != raw.len() {
            return Err(anyhow!("Frame padding validation failed"));
        }

        let payload_bytes = &raw[5..5 + payload_len];
        let frame: Frame = serde_json::from_slice(payload_bytes)?;
        Ok(Some(frame))
    }

    fn apply_mask(&self, data: &mut [u8]) {
        for (i, byte) in data.iter_mut().enumerate() {
            *byte ^= self.mask_key[i % 32];
        }
    }
}
