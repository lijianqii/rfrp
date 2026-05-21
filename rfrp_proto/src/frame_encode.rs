use crate::crypto::Cipher;
use crate::frame_types::RfrpFrame;

impl RfrpFrame {
    /// Serialize RfrpFrame to MessagePack bytes.
    pub fn encode(object: &RfrpFrame) -> Vec<u8> {
        rmp_serde::to_vec(object).expect("Failed to encode RfrpFrame")
    }

    /// Serialize to MessagePack, then encrypt with AES-256-GCM.
    /// Uses in-place encryption to avoid an intermediate ciphertext allocation.
    pub fn encode_encrypted(object: &RfrpFrame, cipher: &Cipher) -> Vec<u8> {
        let mut buf = Self::encode(object);
        cipher.encrypt_in_place(&mut buf);
        buf
    }
}
