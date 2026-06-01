use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress};

/// Compress data using DEFLATE. Returns a new `Vec<u8>` with the compressed output.
pub fn compress(data: &[u8]) -> Vec<u8> {
    let mut c = Compress::new(Compression::best(), false);
    let mut out = Vec::with_capacity(data.len());
    c.compress_vec(data, &mut out, FlushCompress::Finish)
        .expect("Compression failed");
    out
}

/// Decompress data that was compressed with DEFLATE.
/// Returns a `Vec<u8>` with the decompressed output.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut d = Decompress::new(false);
    let mut out = Vec::with_capacity(data.len() * 2);
    d.decompress_vec(data, &mut out, FlushDecompress::Finish)
        .map_err(|e| format!("Decompression failed: {}", e))?;
    Ok(out)
}
