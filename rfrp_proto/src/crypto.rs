use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{AeadInPlace, KeyInit, Tag},
};
use bytes::BytesMut;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};

/// Concrete tag type for AES-256-GCM.
type AesTag = Tag<Aes256Gcm>;

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

    /// Shared encryption logic. Encrypts `data` in-place and returns the
    /// nonce bytes and authentication tag. Works on any `&mut [u8]`.
    fn encrypt_inner(&self, data: &mut [u8]) -> ([u8; 12], AesTag) {
        let counter = self.nonce_counter.fetch_add(1, Ordering::Relaxed);
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&counter.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let tag = self
            .aead
            .encrypt_in_place_detached(nonce, b"", data)
            .expect("Encryption failed");

        (nonce_bytes, tag)
    }

    /// Encrypt plaintext with AES-256-GCM.
    /// Returns: [ciphertext][nonce (12B)][tag (16B)]
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut buf = plaintext.to_vec();
        self.encrypt_in_place(&mut buf);
        buf
    }

    /// Encrypt data in-place on a `Vec<u8>`.
    ///
    /// Input:  `buf` contains plaintext.
    /// Output: `buf` = [ciphertext (same len as plaintext)][nonce (12B)][tag (16B)].
    ///
    /// Nonce is appended at the end to avoid the O(n) memmove that prepending
    /// would require. This is a significant optimization for large frames.
    pub fn encrypt_in_place(&self, buf: &mut Vec<u8>) {
        let (nonce_bytes, tag) = self.encrypt_inner(buf);
        buf.extend_from_slice(&nonce_bytes);
        buf.extend_from_slice(&tag);
    }

    /// Encrypt data in-place on a `BytesMut`.
    ///
    /// Same output format as `encrypt_in_place`: [ciphertext][nonce (12B)][tag (16B)].
    /// Used with the `BytesMut`-based encode path for zero-copy frame sending.
    pub fn encrypt_in_place_bytes_mut(&self, buf: &mut BytesMut) {
        let (nonce_bytes, tag) = self.encrypt_inner(buf);
        buf.extend_from_slice(&nonce_bytes);
        buf.extend_from_slice(&tag);
    }

    /// Decrypt ciphertext that was produced by `encrypt`.
    /// Expects: [ciphertext][nonce (12B)][tag (16B)]
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        if ciphertext.len() < 28 {
            return Err("Ciphertext too short: missing nonce/tag".into());
        }

        let split = ciphertext.len() - 28;
        // Copy nonce and tag into owned arrays to avoid borrow conflicts
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

    /// Decrypt ciphertext in-place on a `Vec<u8>`.
    /// Expects: [ciphertext][nonce (12B)][tag (16B)]
    /// After decryption, `buf` contains plaintext and its length is adjusted.
    /// Returns a reference to the plaintext slice.
    pub fn decrypt_in_place<'a>(&self, buf: &'a mut Vec<u8>) -> Result<&'a [u8], String> {
        if buf.len() < 28 {
            return Err("Ciphertext too short: missing nonce/tag".into());
        }

        let split = buf.len() - 28;
        // Copy nonce and tag into owned arrays to avoid borrow conflicts
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

    /// Decrypt ciphertext in-place on a `BytesMut`.
    /// Expects: [ciphertext][nonce (12B)][tag (16B)]
    /// After decryption, `buf` contains plaintext and its length is adjusted.
    /// Returns a reference to the plaintext slice.
    pub fn decrypt_in_place_bytes_mut<'a>(
        &self,
        buf: &'a mut BytesMut,
    ) -> Result<&'a [u8], String> {
        if buf.len() < 28 {
            return Err("Ciphertext too short: missing nonce/tag".into());
        }

        let split = buf.len() - 28;
        // Copy nonce and tag into owned arrays to avoid borrow conflicts
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
