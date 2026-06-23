use bytes::BytesMut;
use flate2::{Compress, Decompress, FlushCompress, FlushDecompress};

/// Compress data using DEFLATE (zlib format) with a reusable `Compress` struct.
///
/// The `Compress` object is reused across calls to avoid allocating/freeing
/// the internal zlib state (~280KB at level 9) on every frame.
///
/// `compress_tmp` is a reusable scratch buffer for compression output.
pub fn compress_into_bytes_mut(
    data: &[u8],
    dst: &mut BytesMut,
    compress_tmp: &mut Vec<u8>,
    compress: &mut Compress,
) {
    compress.reset();
    dst.clear();
    compress_tmp.clear();
    compress
        .compress_vec(data, compress_tmp, FlushCompress::Finish)
        .expect("Compression failed");
    dst.extend_from_slice(compress_tmp);
}

/// Decompress data using DEFLATE (zlib format) with a reusable `Decompress` struct.
///
/// The `Decompress` object is reused across calls to avoid allocating/freeing
/// the internal zlib state on every frame.
///
/// Output is appended into `dst` (cleared first). The caller reuses `dst`
/// across calls to minimize allocations.
pub fn decompress_into_vec(
    data: &[u8],
    dst: &mut Vec<u8>,
    decompress: &mut Decompress,
) -> Result<(), String> {
    decompress.reset(false);
    dst.clear();
    decompress
        .decompress_vec(data, dst, FlushDecompress::Finish)
        .map_err(|e| format!("Decompression failed: {}", e))?;
    Ok(())
}
