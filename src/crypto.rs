use anyhow::{anyhow, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use x25519_dalek::{PublicKey, StaticSecret};

pub struct Keypair {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl Keypair {
    pub fn generate() -> Self {
        let secret_bytes: [u8; 32] = rand::random();
        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn diffie_hellman(&self, peer_public: &PublicKey) -> [u8; 32] {
        *self.secret.diffie_hellman(peer_public).as_bytes()
    }
}

pub fn derive_session_keys(shared_secret: &[u8; 32], network_secret: &[u8], is_initiator: bool) -> (Key, Key) {
    let mut hasher = blake3::Hasher::new();
    hasher.update(shared_secret);
    hasher.update(network_secret);
    hasher.update(b"veil-v1-session-keys");
    let base = hasher.finalize();

    let mut tx_hasher = blake3::Hasher::new();
    tx_hasher.update(base.as_bytes());
    tx_hasher.update(if is_initiator { b"initiator-tx" } else { b"responder-tx" });
    let tx_key = Key::from(*tx_hasher.finalize().as_bytes());

    let mut rx_hasher = blake3::Hasher::new();
    rx_hasher.update(base.as_bytes());
    rx_hasher.update(if is_initiator { b"responder-tx" } else { b"initiator-tx" });
    let rx_key = Key::from(*rx_hasher.finalize().as_bytes());

    (tx_key, rx_key)
}

pub struct CipherSession {
    cipher: ChaCha20Poly1305,
    nonce_counter: u64,
}

impl CipherSession {
    pub fn new(key: Key) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(&key),
            nonce_counter: 0,
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.next_nonce();
        let mut ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| anyhow!("Encryption error: {e:?}"))?;
        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(nonce.as_slice());
        out.append(&mut ciphertext);
        Ok(out)
    }

    pub fn decrypt(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        if payload.len() < 28 {
            return Err(anyhow!("Payload too short for ciphertext"));
        }
        let nonce_bytes: [u8; 12] = payload[..12]
            .try_into()
            .map_err(|_| anyhow!("Invalid nonce length"))?;
        let nonce = Nonce::from(nonce_bytes);
        let ciphertext = &payload[12..];
        self.cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption error: {e:?}"))
    }

    fn next_nonce(&mut self) -> Nonce {
        self.nonce_counter += 1;
        let mut bytes = [0u8; 12];
        bytes[4..].copy_from_slice(&self.nonce_counter.to_be_bytes());
        Nonce::from(bytes)
    }
}
