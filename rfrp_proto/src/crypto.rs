use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{AeadInPlace, KeyInit, Tag},
};
use bytes::BytesMut;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};

type AesTag = Tag<Aes256Gcm>;

pub struct Cipher {
    aead: Aes256Gcm,
    nonce_counter: AtomicU64,
    random_prefix: [u8; 4],
}

pub fn derive_key(auth_token: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(auth_token.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

pub fn derive_session_key(auth_token: &str, client_nonce: &[u8; 32], server_nonce: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(auth_token.as_bytes());
    hasher.update(b"rfrp-handshake-v1");
    hasher.update(client_nonce);
    hasher.update(server_nonce);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

impl Cipher {
    pub fn new(key: &[u8; 32]) -> Self {
        let random_prefix: [u8; 4] = rand::random();
        Self {
            aead: Aes256Gcm::new_from_slice(key).expect("Invalid key length for AES-256-GCM"),
            nonce_counter: AtomicU64::new(0),
            random_prefix,
        }
    }

    fn encrypt_inner(&self, data: &mut [u8]) -> ([u8; 12], AesTag) {
        let counter = self.nonce_counter.fetch_add(1, Ordering::Relaxed);
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&self.random_prefix);
        nonce_bytes[4..12].copy_from_slice(&counter.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let tag = self
            .aead
            .encrypt_in_place_detached(nonce, b"", data)
            .expect("Encryption failed");

        (nonce_bytes, tag)
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut buf = plaintext.to_vec();
        self.encrypt_in_place(&mut buf);
        buf
    }

    pub fn encrypt_in_place(&self, buf: &mut Vec<u8>) {
        let (nonce_bytes, tag) = self.encrypt_inner(buf);
        buf.extend_from_slice(&nonce_bytes);
        buf.extend_from_slice(&tag);
    }

    pub fn encrypt_in_place_bytes_mut(&self, buf: &mut BytesMut) {
        let (nonce_bytes, tag) = self.encrypt_inner(buf);
        buf.extend_from_slice(&nonce_bytes);
        buf.extend_from_slice(&tag);
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        if ciphertext.len() < 28 {
            return Err("Ciphertext too short: missing nonce/tag".into());
        }

        let split = ciphertext.len() - 28;
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&ciphertext[split..split + 12]);
        let mut tag_bytes = [0u8; 16];
        tag_bytes.copy_from_slice(&ciphertext[split + 12..]);

        let mut plaintext = ciphertext[..split].to_vec();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let tag = AesTag::from_slice(&tag_bytes);

        self.aead
            .decrypt_in_place_detached(nonce, b"", &mut plaintext, tag)
            .map_err(|e| format!("Decryption failed: {}", e))?;

        Ok(plaintext)
    }

    pub fn decrypt_in_place<'a>(&self, buf: &'a mut Vec<u8>) -> Result<&'a [u8], String> {
        if buf.len() < 28 {
            return Err("Ciphertext too short: missing nonce/tag".into());
        }

        let split = buf.len() - 28;
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&buf[split..split + 12]);
        let mut tag_bytes = [0u8; 16];
        tag_bytes.copy_from_slice(&buf[split + 12..]);

        buf.truncate(split);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let tag = AesTag::from_slice(&tag_bytes);

        self.aead
            .decrypt_in_place_detached(nonce, b"", buf.as_mut_slice(), tag)
            .map_err(|e| format!("Decryption failed: {}", e))?;

        Ok(buf.as_slice())
    }

    pub fn decrypt_in_place_bytes_mut<'a>(
        &self,
        buf: &'a mut BytesMut,
    ) -> Result<&'a [u8], String> {
        if buf.len() < 28 {
            return Err("Ciphertext too short: missing nonce/tag".into());
        }

        let split = buf.len() - 28;
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&buf[split..split + 12]);
        let mut tag_bytes = [0u8; 16];
        tag_bytes.copy_from_slice(&buf[split + 12..]);

        buf.truncate(split);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let tag = AesTag::from_slice(&tag_bytes);

        self.aead
            .decrypt_in_place_detached(nonce, b"", &mut buf[..], tag)
            .map_err(|e| format!("Decryption failed: {}", e))?;

        Ok(&buf[..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_uniqueness_across_ciphers() {
        let key = derive_key("test");
        let c1 = Cipher::new(&key);
        let c2 = Cipher::new(&key);

        let data = b"hello";
        let enc1 = c1.encrypt(data);
        let enc2 = c2.encrypt(data);

        let n1 = &enc1[enc1.len() - 28..enc1.len() - 16];
        let n2 = &enc2[enc2.len() - 28..enc2.len() - 16];

        let prefix1 = u32::from_be_bytes([n1[0], n1[1], n1[2], n1[3]]);
        let prefix2 = u32::from_be_bytes([n2[0], n2[1], n2[2], n2[3]]);
        assert_ne!(prefix1, prefix2, "random nonce prefixes must differ");
    }

    #[test]
    fn session_key_derives_different_per_connection() {
        let k1 = derive_session_key("token", &[1u8; 32], &[2u8; 32]);
        let k2 = derive_session_key("token", &[3u8; 32], &[4u8; 32]);
        assert_ne!(k1, k2, "different nonces must produce different keys");
    }

    #[test]
    fn session_key_symmetric() {
        let k1 = derive_session_key("token", &[1u8; 32], &[2u8; 32]);
        let k2 = derive_session_key("token", &[1u8; 32], &[2u8; 32]);
        assert_eq!(k1, k2, "same inputs must produce same key");
    }
}
