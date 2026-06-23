use crate::compress;
use crate::crypto::Cipher;
use crate::frame_types::RfrpFrame;

impl RfrpFrame {
    /// Deserialize RfrpFrame from MessagePack bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        rmp_serde::from_slice(bytes).map_err(|e| format!("Failed to decode frame: {}", e))
    }

    /// Decrypt AES-256-GCM ciphertext, decompress with DEFLATE, then deserialize.
    ///
    /// Decrypts `buf` in-place (BytesMut from the codec). Uses a reusable
    /// `Decompress` struct to avoid allocating the zlib decompression state
    /// on every frame. `decomp_buf` is a reusable `Vec<u8>` for decompression
    /// output, avoiding per-frame allocation.
    ///
    /// Pipeline: AES-256-GCM decrypt → DEFLATE decompress → MessagePack deserialize
    pub fn decode_encrypted_bytes_mut(
        buf: &mut bytes::BytesMut,
        cipher: &Cipher,
        decomp_buf: &mut Vec<u8>,
        decompress: &mut flate2::Decompress,
    ) -> Result<Self, String> {
        let plaintext = cipher.decrypt_in_place_bytes_mut(buf)?;
        compress::decompress_into_vec(plaintext, decomp_buf, decompress)?;
        Self::decode(decomp_buf)
    }
}
