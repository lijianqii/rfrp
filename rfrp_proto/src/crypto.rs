use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use sha2::{Sha256, Digest};
use rand::Rng;

/// Derive a 32-byte AES-256 key from the auth_token via SHA-256.
pub fn derive_key(auth_token: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(auth_token.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Encrypt plaintext with AES-256-GCM.
/// Returns: [nonce (12 bytes)][ciphertext + tag]
pub fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .expect("Invalid key length for AES-256-GCM");

    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("Encryption failed");

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    result
}

/// Decrypt ciphertext that was produced by `encrypt`.
/// Expects: [nonce (12 bytes)][ciphertext + tag]
pub fn decrypt(ciphertext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    if ciphertext.len() < 12 {
        return Err("Ciphertext too short: missing nonce".into());
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .expect("Invalid key length for AES-256-GCM");

    let (nonce_bytes, encrypted) = ciphertext.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, encrypted)
        .map_err(|e| format!("Decryption failed: {}", e))
}
