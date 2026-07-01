use bytes::BytesMut;
use flate2::{Compress, Decompress, FlushCompress, FlushDecompress, Status};

pub const MAX_DECOMPRESSED_SIZE: usize = 64 * 1024 * 1024;

pub fn compress_into_bytes_mut(data: &[u8], dst: &mut BytesMut, compress: &mut Compress) {
    compress.reset();
    dst.clear();

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

pub fn decompress_into_vec(
    data: &[u8],
    dst: &mut Vec<u8>,
    decompress: &mut Decompress,
) -> Result<(), String> {
    decompress.reset(false);
    dst.clear();

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
        if dst.len() > MAX_DECOMPRESSED_SIZE {
            return Err(format!(
                "Decompression bomb detected: output exceeded {} bytes",
                MAX_DECOMPRESSED_SIZE
            ));
        }
        input = &input[in_consumed..];
        if status == Status::StreamEnd {
            break;
        }
        if in_consumed == 0 && out_written == 0 {
            return Err("Decompression stalled: incomplete input stream".to_string());
        }
    }
    Ok(())
}
