use crate::frame_types::RfrpFrame;
use crate::crypto::Cipher;

impl RfrpFrame {
    /// Deserialize RfrpFrame from JSON bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes)
            .map_err(|e| format!("Failed to decode frame: {}", e))
    }

    /// Decrypt AES-256-GCM ciphertext, then deserialize into RfrpFrame.
    pub fn decode_encrypted(bytes: &[u8], cipher: &Cipher) -> Result<Self, String> {
        let plaintext = cipher.decrypt(bytes)?;
        Self::decode(&plaintext)
    }
}
