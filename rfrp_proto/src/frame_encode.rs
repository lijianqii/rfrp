use crate::frame_types::RfrpFrame;
use crate::crypto::Cipher;

impl RfrpFrame {
    /// Serialize RfrpFrame to JSON bytes.
    pub fn encode(object: &RfrpFrame) -> Vec<u8> {
        serde_json::to_vec(object).expect("Failed to encode RfrpFrame")
    }

    /// Serialize RfrpFrame to JSON bytes, then encrypt with AES-256-GCM.
    pub fn encode_encrypted(object: &RfrpFrame, cipher: &Cipher) -> Vec<u8> {
        let plaintext = Self::encode(object);
        cipher.encrypt(&plaintext)
    }
}
