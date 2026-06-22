use bytes::BytesMut;
use crate::compress;
use crate::crypto::Cipher;
use crate::frame_types::RfrpFrame;

impl RfrpFrame {
    /// Deserialize RfrpFrame from MessagePack bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        rmp_serde::from_slice(bytes).map_err(|e| format!("Failed to decode frame: {}", e))
    }

    /// Decrypt AES-256-GCM ciphertext, decompress with DEFLATE, then deserialize.
    /// Accepts a `Vec<u8>` buffer (e.g. from the codec) and decrypts in-place
    /// to avoid allocating a separate plaintext buffer.
    ///
    /// `decomp_buf` is a reusable buffer for decompression output, avoiding
    /// per-frame allocation on the hot path.
    ///
    /// Pipeline: AES-256-GCM decrypt → DEFLATE decompress → MessagePack deserialize
    pub fn decode_encrypted(
        buf: &mut Vec<u8>,
        cipher: &Cipher,
        decomp_buf: &mut Vec<u8>,
    ) -> Result<Self, String> {
        let plaintext = cipher.decrypt_in_place(buf)?;
        compress::decompress_into(plaintext, decomp_buf)?;
        Self::decode(decomp_buf)
    }

    /// Decrypt AES-256-GCM ciphertext from a `BytesMut` buffer, decompress, then deserialize.
    /// Decrypts in-place; decompresses into `decomp_buf` (reused across calls).
    /// Zero-copy: the codec produces `BytesMut` and we avoid the `Vec<u8>` conversion.
    ///
    /// Pipeline: AES-256-GCM decrypt → DEFLATE decompress → MessagePack deserialize
    pub fn decode_encrypted_bytes_mut(
        buf: &mut BytesMut,
        cipher: &Cipher,
        decomp_buf: &mut BytesMut,
    ) -> Result<Self, String> {
        let plaintext = cipher.decrypt_in_place_bytes_mut(buf)?;
        compress::decompress_into_bytes_mut(plaintext, decomp_buf)?;
        Self::decode(decomp_buf)
    }
}
