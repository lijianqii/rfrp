use log::{error, info, warn};
use tokio::net::TcpStream;
use tokio::task::{self, JoinHandle};
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use tokio_stream::StreamExt;
use rfrp_proto::frame_types::RfrpFrame;
use tokio::sync::mpsc;
use futures::SinkExt;
use rfrp_proto::frame_handle::{handle_reg_frame, RoutingTable};
use rfrp_proto::crypto;
use bytes::Bytes;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::Mutex;

pub async fn run_proxy(client: TcpStream, auth_token: String) {
    let key = crypto::derive_key(&auth_token);
    info!("Auth token configured, encryption enabled");

    let (reader, writer) = client.into_split();

    let mut reader = FramedRead::new(reader, LengthDelimitedCodec::new());
    let mut writer = FramedWrite::new(writer, LengthDelimitedCodec::new());

    let (tx_channel, mut rx_channel) = mpsc::channel::<RfrpFrame>(128);

    // Shared routing table: conn_id → sender to external connection
    let routing_table: RoutingTable = Arc::new(Mutex::new(HashMap::new()));

    // Track proxy listener tasks so we can abort them on disconnect
    let mut proxy_tasks: Vec<JoinHandle<()>> = Vec::new();

    // Spawn write task: sends encrypted frames to the client
    task::spawn(async move {
        while let Some(frame) = rx_channel.recv().await {
            let bytes = RfrpFrame::encode_encrypted(&frame, &key);
            if let Err(e) = writer.send(Bytes::from(bytes)).await {
                error!("Failed to send frame to client: {}", e);
                break;
            }
        }
    });

    // Main read loop: receive frames from the client
    loop {
        let bytes = match reader.next().await {
            Some(Ok(bytes)) => bytes,
            Some(Err(e)) => {
                error!("Read error from client: {}", e);
                break;
            }
            None => {
                info!("Client closed connection");
                break;
            }
        };

        let frame = match RfrpFrame::decode_encrypted(&bytes, &key) {
            Ok(frame) => frame,
            Err(e) => {
                error!("Failed to decode frame from client: {}", e);
                continue;
            }
        };

        match frame {
            RfrpFrame::Register(client_info) => {
                info!("Client registered proxy: {:?}", client_info.get_name());
                let routing = routing_table.clone();
                let tx = tx_channel.clone();
                let handle = task::spawn(async move {
                    handle_reg_frame(client_info, tx, routing).await;
                });
                proxy_tasks.push(handle);
            }
            RfrpFrame::Control(control_info) => {
                info!("Control info: {:?}", control_info);
            }
            RfrpFrame::RegisterAck(_) => {
                warn!("Unexpected RegisterAck frame received on server");
            }
            RfrpFrame::Data(data_info) => {
                // Route response data from client back to the correct external connection
                let routing = routing_table.lock().await;
                match routing.get(&data_info.conn_id) {
                    Some(sender) => {
                        if let Err(e) = sender.send(data_info.data).await {
                            error!(
                                "Failed to route response data to conn {}: {}",
                                data_info.conn_id, e
                            );
                        }
                    }
                    None => {
                        error!(
                            "No route found for conn {} (proxy '{}'), connection may have been closed",
                            data_info.conn_id,
                            data_info.client.get_name()
                        );
                    }
                }
            }
        }
    }

    // Abort all proxy listener tasks to release bound ports
    for handle in proxy_tasks {
        handle.abort();
    }
    info!("Server proxy session ended");
}
