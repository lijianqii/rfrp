use bytes::Bytes;
use futures::SinkExt;
use log::error;
use std::sync::Arc;

use crate::crypto::Cipher;
use crate::frame_types::RfrpFrame;

/// Spawn a simple FIFO write task.
///
/// Returns an mpsc sender and the task's JoinHandle.
/// The write task encodes and encrypts each frame then sends it.
/// This is intentionally a plain FIFO — for RDP, priority queuing
/// and coalescing add overhead without benefit because RDP already
/// performs its own framing and flow control.
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
        while let Some(frame) = rx.recv().await {
            let bytes = RfrpFrame::encode_encrypted(&frame, &cipher);
            if let Err(e) = writer.send(Bytes::from(bytes)).await {
                error!("Failed to send encrypted frame: {}", e);
                break;
            }
        }
    });

    (tx, handle)
}
