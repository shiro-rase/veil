use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceStatus {
    Pending,
    Approved,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: String,
    pub public_key: String,
    pub role: String,
    pub status: DeviceStatus,
    pub enrolled_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinToken {
    pub token: String,
    pub role: String,
    pub expires_at: u64,
    pub auto_approve: bool,
}

#[derive(Clone, Default)]
pub struct TokenManager {
    tokens: Arc<RwLock<HashMap<String, JoinToken>>>,
    devices: Arc<RwLock<HashMap<String, DeviceInfo>>>,
}

impl TokenManager {
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
            devices: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn create_token(&self, role: String, ttl_secs: u64, auto_approve: bool) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let rand_bytes: [u8; 16] = rand::random();
        let token = format!("veil-tok-{}", hex::encode(rand_bytes));

        let join_token = JoinToken {
            token: token.clone(),
            role,
            expires_at: now + ttl_secs,
            auto_approve,
        };

        self.tokens.write().await.insert(token.clone(), join_token);
        token
    }

    pub async fn enroll_device(
        &self,
        token_str: &str,
        device_id: String,
        public_key: String,
    ) -> Result<DeviceStatus> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut tokens_lock = self.tokens.write().await;
        let token_obj = tokens_lock
            .get(token_str)
            .ok_or_else(|| anyhow!("Token not found or already consumed"))?;

        if now > token_obj.expires_at {
            tokens_lock.remove(token_str);
            return Err(anyhow!("Token has expired"));
        }

        let role = token_obj.role.clone();
        let initial_status = if token_obj.auto_approve {
            DeviceStatus::Approved
        } else {
            DeviceStatus::Pending
        };

        tokens_lock.remove(token_str);

        let info = DeviceInfo {
            device_id: device_id.clone(),
            public_key,
            role,
            status: initial_status.clone(),
            enrolled_at: now,
        };

        self.devices.write().await.insert(device_id, info);
        Ok(initial_status)
    }

    pub async fn approve_device(&self, device_id: &str) -> Result<()> {
        let mut map = self.devices.write().await;
        let dev = map
            .get_mut(device_id)
            .ok_or_else(|| anyhow!("Device not found: {device_id}"))?;
        dev.status = DeviceStatus::Approved;
        Ok(())
    }

    pub async fn revoke_device(&self, device_id: &str) -> Result<()> {
        let mut map = self.devices.write().await;
        let dev = map
            .get_mut(device_id)
            .ok_or_else(|| anyhow!("Device not found: {device_id}"))?;
        dev.status = DeviceStatus::Revoked;
        Ok(())
    }

    pub async fn is_approved(&self, device_id: &str) -> bool {
        let map = self.devices.read().await;
        matches!(
            map.get(device_id).map(|d| &d.status),
            Some(DeviceStatus::Approved)
        )
    }

    pub async fn list_devices(&self) -> Vec<DeviceInfo> {
        let map = self.devices.read().await;
        map.values().cloned().collect()
    }
}
