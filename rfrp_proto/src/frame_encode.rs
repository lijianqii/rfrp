use bytes::{Bytes, BytesMut};
use std::io;

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

    /// Serialize to MessagePack, then encrypt with AES-256-GCM.
    /// Uses a reusable `BytesMut` buffer to achieve zero-allocation on the
    /// hot path (after the initial warmup frames fill the buffer capacity).
    ///
    /// The buffer is cleared and reused each call. After a few frames it
    /// reaches a stable capacity and no further heap allocations occur.
    /// `BytesMut::split().freeze()` yields `Bytes` with zero-copy.
    pub fn encode_encrypted(object: &RfrpFrame, cipher: &Cipher, buf: &mut BytesMut) -> Bytes {
        buf.clear();
        {
            let mut writer = BytesMutWriter(&mut *buf);
            rmp_serde::encode::write(&mut writer, object).expect("Failed to encode RfrpFrame");
        }
        cipher.encrypt_in_place_bytes_mut(buf);
        buf.split().freeze()
    }
}
