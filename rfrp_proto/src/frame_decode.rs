use crate::frame_types::RfrpFrame;
use crate::crypto;

impl RfrpFrame {
    /// Deserialize RfrpFrame from JSON bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let json = std::str::from_utf8(bytes)
            .map_err(|e| format!("Invalid UTF-8: {}", e))?;
        serde_json::from_str(json)
            .map_err(|e| format!("Failed to decode frame: {}", e))
    }

    /// Decrypt AES-256-GCM ciphertext, then deserialize into RfrpFrame.
    pub fn decode_encrypted(bytes: &[u8], key: &[u8; 32]) -> Result<Self, String> {
        let plaintext = crypto::decrypt(bytes, key)?;
        Self::decode(&plaintext)
    }
}
