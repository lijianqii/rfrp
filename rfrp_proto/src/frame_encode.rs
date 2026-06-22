use bytes::{Bytes, BytesMut};
use std::io;

use crate::compress;
use crate::crypto::Cipher;
use crate::frame_types::RfrpFrame;

/// Thin wrapper that implements `std::io::Write` for `BytesMut`,
/// allowing `rmp_serde::to_writer` to serialize directly into a `BytesMut`
/// buffer without an intermediate `Vec` allocation.
struct BytesMutWriter<'a>(&'a mut BytesMut);

impl<'a> io::Write for BytesMutWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl RfrpFrame {
    /// Serialize RfrpFrame to MessagePack bytes.
    pub fn encode(object: &RfrpFrame) -> Vec<u8> {
        rmp_serde::to_vec(object).expect("Failed to encode RfrpFrame")
    }

    /// Serialize to MessagePack, compress with DEFLATE, then encrypt with AES-256-GCM.
    /// Uses a reusable `BytesMut` buffer to minimize allocations on the hot path.
    ///
    /// Pipeline: MessagePack → DEFLATE compress → AES-256-GCM encrypt
    /// Output format: [compressed ciphertext][nonce (12B)][tag (16B)]
    pub fn encode_encrypted(object: &RfrpFrame, cipher: &Cipher, buf: &mut BytesMut) -> Bytes {
        buf.clear();
        {
            let mut writer = BytesMutWriter(&mut *buf);
            rmp_serde::encode::write(&mut writer, object).expect("Failed to encode RfrpFrame");
        }
        // Split off the serialized payload (zero-copy), then compress
        // directly back into the now-empty buffer.
        let serialized = buf.split();
        compress::compress_into_bytes_mut(&serialized, buf);
        cipher.encrypt_in_place_bytes_mut(buf);
        buf.split().freeze()
    }
}
