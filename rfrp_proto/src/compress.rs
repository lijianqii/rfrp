use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use std::io::{Read, Write};

/// Compress data using DEFLATE (zlib format, max compression level).
/// Returns a new `Vec<u8>` with the compressed output.
pub fn compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = DeflateEncoder::new(Vec::with_capacity(data.len()), Compression::best());
    encoder.write_all(data).expect("Compression write failed");
    encoder.finish().expect("Compression finish failed")
}

/// Decompress data that was compressed with the corresponding `compress()`.
/// Returns a `Vec<u8>` with the decompressed output.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder = DeflateDecoder::new(data);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| format!("Decompression failed: {}", e))?;
    Ok(out)
}
