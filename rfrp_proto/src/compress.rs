use bytes::BytesMut;
use flate2::{Compress, Decompress, FlushCompress, FlushDecompress, Status};

/// Compress data using DEFLATE (zlib format) with a reusable `Compress` struct.
///
/// The `Compress` object is reused across calls to avoid allocating/freeing
/// the internal zlib state (~280KB at level 9) on every frame.
///
/// Compressed output is written directly into `dst` (cleared first).
pub fn compress_into_bytes_mut(
    data: &[u8],
    dst: &mut BytesMut,
    compress: &mut Compress,
) {
    compress.reset();
    dst.clear();

    // Drive the compression in a loop with a fixed stack buffer, appending
    // each produced chunk directly to `dst` (which grows on demand) until the
    // whole stream is flushed.
    let mut input = data;
    let mut chunk = [0u8; 8192];
    loop {
        let before_in = compress.total_in();
        let before_out = compress.total_out();
        let status = compress
            .compress(input, &mut chunk, FlushCompress::Finish)
            .expect("Compression failed");
        let in_consumed = (compress.total_in() - before_in) as usize;
        let out_written = (compress.total_out() - before_out) as usize;
        dst.extend_from_slice(&chunk[..out_written]);
        input = &input[in_consumed..];
        if status == Status::StreamEnd {
            break;
        }
        if in_consumed == 0 && out_written == 0 {
            panic!("Compression stalled with no progress");
        }
    }
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

    // NOTE: `Decompress::decompress_vec` only writes to the *spare capacity* of
    // `dst` and never grows it. When `dst` starts empty (capacity 0) the call
    // produces zero bytes — silently dropping the entire payload, which broke
    // the whole tunnel (every frame decoded to empty msgpack). Drive the
    // decompression in a loop with a fixed stack buffer instead, appending each
    // produced chunk to `dst` (which grows on demand) until the stream ends.
    let mut input = data;
    let mut chunk = [0u8; 8192];
    loop {
        let before_in = decompress.total_in();
        let before_out = decompress.total_out();
        let status = decompress
            .decompress(input, &mut chunk, FlushDecompress::Finish)
            .map_err(|e| format!("Decompression failed: {}", e))?;
        let in_consumed = (decompress.total_in() - before_in) as usize;
        let out_written = (decompress.total_out() - before_out) as usize;
        dst.extend_from_slice(&chunk[..out_written]);
        input = &input[in_consumed..];
        if status == Status::StreamEnd {
            break;
        }
        if in_consumed == 0 && out_written == 0 {
            // No progress: the input stream is incomplete or truncated.
            return Err("Decompression stalled: incomplete input stream".to_string());
        }
    }
    Ok(())
}
