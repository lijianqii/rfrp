use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, AeadInPlace, KeyInit},
};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};

/// Pre-computed AES-256-GCM cipher for a given key.
/// Create once per connection and reuse for all encrypt/decrypt calls.
pub struct Cipher {
    aead: Aes256Gcm,
    /// Atomic counter for generating unique nonces without CSPRNG overhead.
    /// 64-bit counter allows 2^64 unique encryptions per connection.
    nonce_counter: AtomicU64,
}

/// Derive a 32-byte AES-256 key from the auth_token via SHA-256.
pub fn derive_key(auth_token: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(auth_token.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

impl Cipher {
    /// Create a new Cipher from a 32-byte key. The AES key schedule is
    /// computed once here and reused for all subsequent operations.
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            aead: Aes256Gcm::new_from_slice(key).expect("Invalid key length for AES-256-GCM"),
            nonce_counter: AtomicU64::new(0),
        }
    }

    /// Encrypt plaintext with AES-256-GCM.
    /// Uses an atomic counter for the nonce instead of CSPRNG, which is:
    /// - Faster (no syscall / CSPRNG overhead per frame)
    /// - Equally secure for GCM (only requires uniqueness, not randomness)
    /// Returns: [nonce (12 bytes)][ciphertext + tag]
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut buf = plaintext.to_vec();
        self.encrypt_in_place(&mut buf);
        buf
    }

    /// Encrypt data in-place.
    ///
    /// Input:  `buf` contains plaintext.
    /// Output: `buf` = [nonce (12B)][ciphertext (same len as plaintext)][tag (16B)].
    ///
    /// This avoids allocating a separate ciphertext buffer — the plaintext is
    /// encrypted in-place, then shifted right 12 bytes to make room for the nonce,
    /// and the 16-byte tag is appended.
    pub fn encrypt_in_place(&self, buf: &mut Vec<u8>) {
        // 64-bit counter (big-endian) + 4 zero bytes = 12-byte unique nonce
        let counter = self.nonce_counter.fetch_add(1, Ordering::Relaxed);
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&counter.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt plaintext in-place, get detached tag
        let tag = self
            .aead
            .encrypt_in_place_detached(nonce, b"", buf)
            .expect("Encryption failed");

        // buf now contains ciphertext (same length as original plaintext).
        // Make room: shift ciphertext right 12 bytes for nonce, append 16-byte tag.
        let ciphertext_len = buf.len();
        buf.resize(ciphertext_len + 12 + 16, 0);
        buf.copy_within(0..ciphertext_len, 12);
        buf[..12].copy_from_slice(&nonce_bytes);
        buf[ciphertext_len + 12..].copy_from_slice(&tag);
    }

    /// Decrypt ciphertext that was produced by `encrypt`.
    /// Expects: [nonce (12 bytes)][ciphertext + tag]
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        if ciphertext.len() < 12 {
            return Err("Ciphertext too short: missing nonce".into());
        }

        let (nonce_bytes, encrypted) = ciphertext.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        self.aead
            .decrypt(nonce, encrypted)
            .map_err(|e| format!("Decryption failed: {}", e))
    }
}
