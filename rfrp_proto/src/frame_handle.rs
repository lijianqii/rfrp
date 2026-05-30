use bytes::{Bytes, BytesMut};
use log::{error, info, warn};
use rfrp_config::config_info::base_types::ClientInfo;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, mpsc};
use tokio::task;

use crate::frame_types::RfrpFrame;

use tokio::sync::mpsc::Sender;

type ConnSender = mpsc::Sender<Bytes>;
pub type RoutingTable = Arc<Mutex<HashMap<u64, ConnSender>>>;

pub async fn handle_reg_frame(
    client_info: ClientInfo,
    tx_channel: Sender<RfrpFrame>,
    routing_table: RoutingTable,
) {
    let client_info = Arc::new(client_info);
    let proxy_name: Arc<str> = Arc::from(client_info.get_name());
    let listener = match TcpListener::bind(format!("0.0.0.0:{}", client_info.get_bind_port())).await
    {
        Ok(listener) => {
            info!(
                "Proxy '{}' bound to port {}",
                proxy_name,
                client_info.get_bind_port()
            );
            listener
        }
        Err(e) => {
            error!(
                "Failed to bind proxy '{}' on port {}: {}",
                proxy_name,
                client_info.get_bind_port(),
                e
            );
            // Notify client that registration failed
            let reject = RfrpFrame::new_reg_ack_frame(&client_info, false);
            let _ = tx_channel.send(reject).await;
            return;
        }
    };

    // Confirm registration to client
    let confirm = RfrpFrame::new_reg_ack_frame(&client_info, true);
    if tx_channel.send(confirm).await.is_err() {
        error!("Failed to send registration confirmation, channel closed");
        return;
    }

    let mut next_conn_id: u64 = 0;

    loop {
        let (remote, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!("Proxy '{}' failed to accept connection: {}", proxy_name, e);
                continue;
            }
        };

        let conn_id = next_conn_id;
        next_conn_id = next_conn_id.wrapping_add(1);

        info!(
            "Proxy '{}': accepted external conn {} from {}",
            proxy_name, conn_id, peer
        );

        // Disable Nagle's algorithm for low-latency RDP forwarding
        if let Err(e) = remote.set_nodelay(true) {
            warn!("Failed to set TCP_NODELAY on external socket: {}", e);
        }

        let (mut remote_read, remote_write) = remote.into_split();
        let tx_channel = tx_channel.clone();
        let routing = routing_table.clone();

        // Create a channel for writing data back to this external connection
        let (tx_to_remote, mut rx_to_remote) = mpsc::channel::<Bytes>(256);

        // Register this connection in the routing table
        routing.lock().await.insert(conn_id, tx_to_remote);

        // Spawn read task: external user → client
        let tx = tx_channel.clone();
        let proxy_name_read = Arc::clone(&proxy_name);
        let cid = conn_id;
        let routing_cleanup = routing.clone();
        task::spawn(async move {
            let mut buf = BytesMut::with_capacity(65536);
            loop {
                match remote_read.read_buf(&mut buf).await {
                    Ok(0) => {
                        info!(
                            "Proxy '{}' conn {}: external peer {} closed connection",
                            proxy_name_read, cid, peer
                        );
                        break;
                    }
                    Ok(_) => {
                        let data = buf.split().freeze();
                        let frame = RfrpFrame::new_data_frame(data, &proxy_name_read, cid);
                        if tx.send(frame).await.is_err() {
                            error!(
                                "Proxy '{}' conn {}: failed to send data frame to client, channel closed",
                                proxy_name_read, cid
                            );
                            break;
                        }
                    }
                    Err(e) => {
                        error!(
                            "Proxy '{}' conn {}: read error from external: {}",
                            proxy_name_read, cid, e
                        );
                        break;
                    }
                }
            }
            // Cleanup: remove from routing table on disconnect
            routing_cleanup.lock().await.remove(&cid);
            info!(
                "Proxy '{}' conn {}: cleaned up from routing table",
                proxy_name_read, cid
            );
        });

        // Spawn write task: client → external user
        // Wraps the write half in BufWriter to reduce syscall overhead
        // for small frames arriving in quick succession.
        let proxy_name_write = Arc::clone(&proxy_name);
        let cid = conn_id;
        task::spawn(async move {
            let mut remote_write = BufWriter::new(remote_write);
            while let Some(data) = rx_to_remote.recv().await {
                if let Err(e) = remote_write.write_all(&data).await {
                    error!(
                        "Proxy '{}' conn {}: write error to external: {}",
                        proxy_name_write, cid, e
                    );
                    break;
                }
                // Flush after each complete message to ensure timely delivery
                let _ = remote_write.flush().await;
            }
            info!(
                "Proxy '{}' conn {}: write task ended",
                proxy_name_write, cid
            );
        });
    }
}
