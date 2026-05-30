use crate::crypto::Cipher;
use crate::frame_types::RfrpFrame;

impl RfrpFrame {
    /// Deserialize RfrpFrame from MessagePack bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        rmp_serde::from_slice(bytes).map_err(|e| format!("Failed to decode frame: {}", e))
    }

    /// Decrypt AES-256-GCM ciphertext in-place, then deserialize into RfrpFrame.
    /// Accepts a `Vec<u8>` buffer (e.g. from the codec) and decrypts in-place
    /// to avoid allocating a separate plaintext buffer.
    pub fn decode_encrypted(buf: &mut Vec<u8>, cipher: &Cipher) -> Result<Self, String> {
        let plaintext = cipher.decrypt_in_place(buf)?;
        Self::decode(plaintext)
    }
}
