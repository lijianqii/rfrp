use bytes::BytesMut;
use futures::SinkExt;
use log::error;
use std::sync::Arc;

use crate::crypto::Cipher;
use crate::frame_types::RfrpFrame;

/// Spawn a simple FIFO write task.
///
/// Returns an mpsc sender and the task's JoinHandle.
/// The write task encodes and encrypts each frame then sends it.
/// Uses a reusable `BytesMut` buffer to minimize allocations on the hot path.
pub fn spawn_write_task(
    writer: tokio_util::codec::FramedWrite<
        tokio::net::tcp::OwnedWriteHalf,
        tokio_util::codec::LengthDelimitedCodec,
    >,
    cipher: Arc<Cipher>,
) -> (
    tokio::sync::mpsc::Sender<RfrpFrame>,
    tokio::task::JoinHandle<()>,
) {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<RfrpFrame>(256);

    let handle = tokio::task::spawn(async move {
        let mut writer = writer;
        let mut encode_buf = BytesMut::with_capacity(65536);
        while let Some(frame) = rx.recv().await {
            let bytes = RfrpFrame::encode_encrypted(&frame, &cipher, &mut encode_buf);
            if let Err(e) = writer.send(bytes).await {
                error!("Failed to send encrypted frame: {}", e);
                break;
            }
        }
    });

    (tx, handle)
}
