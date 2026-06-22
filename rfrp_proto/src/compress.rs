use bytes::BytesMut;
use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use std::io::{Read, Write};

/// Compress data using DEFLATE (zlib format).
/// Writes compressed output directly into `dst`, reusing its capacity.
pub fn compress_into(data: &[u8], dst: &mut Vec<u8>) {
    dst.clear();
    let mut encoder = DeflateEncoder::new(dst, Compression::best());
    encoder.write_all(data).expect("Compression write failed");
    encoder.finish().expect("Compression finish failed");
}

/// Compress data using DEFLATE (zlib format), into a `BytesMut` buffer.
/// Reuses capacity; no intermediate allocation.
pub fn compress_into_bytes_mut(data: &[u8], dst: &mut BytesMut) {
    struct Writer<'a>(&'a mut BytesMut);
    impl<'a> Write for Writer<'a> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    dst.clear();
    let writer = Writer(dst);
    let mut encoder = DeflateEncoder::new(writer, Compression::best());
    encoder.write_all(data).expect("Compression write failed");
    encoder.finish().expect("Compression finish failed");
}

/// Compress data using DEFLATE (zlib format).
/// Retained for non-reusable-buffer callers; prefer `compress_into`.
pub fn compress(data: &[u8]) -> Vec<u8> {
    let mut dst = Vec::with_capacity(data.len());
    compress_into(data, &mut dst);
    dst
}

/// Decompress data that was compressed with the corresponding `compress*()`.
/// Writes decompressed output directly into `dst`, reusing its capacity.
pub fn decompress_into(data: &[u8], dst: &mut Vec<u8>) -> Result<(), String> {
    dst.clear();
    // Reserve reasonable capacity to minimize reallocations
    dst.reserve(data.len() * 2);
    let mut decoder = DeflateDecoder::new(data);
    decoder
        .read_to_end(dst)
        .map_err(|e| format!("Decompression failed: {}", e))?;
    Ok(())
}

/// Decompress data into a `BytesMut` buffer. Reuses capacity.
pub fn decompress_into_bytes_mut(data: &[u8], dst: &mut BytesMut) -> Result<(), String> {
    dst.clear();
    dst.reserve(data.len() * 2);
    let mut decoder = DeflateDecoder::new(data);
    let mut buf = [0u8; 8192];
    loop {
        let n = decoder
            .read(&mut buf)
            .map_err(|e| format!("Decompression failed: {}", e))?;
        if n == 0 {
            break;
        }
        dst.extend_from_slice(&buf[..n]);
    }
    Ok(())
}

/// Decompress data that was compressed with the corresponding `compress*()`.
/// Retained for non-reusable-buffer callers; prefer `decompress_into`.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut dst = Vec::new();
    decompress_into(data, &mut dst)?;
    Ok(dst)
}
