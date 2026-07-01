pub mod coalesce;
pub mod compress;
pub mod crypto;
pub mod frame_decode;
pub mod frame_encode;
pub mod frame_handle;
pub mod frame_types;
pub mod handshake;

pub use frame_handle::RoutingTable;

pub const MAX_FRAME_LEN: usize = 1024 * 1024;

pub fn make_length_delimited_codec() -> tokio_util::codec::LengthDelimitedCodec {
    let mut codec = tokio_util::codec::LengthDelimitedCodec::new();
    codec.set_max_frame_length(MAX_FRAME_LEN);
    codec
}
