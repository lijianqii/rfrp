use log::{error, info};
use rfrp_config::config_info::base_types::ClientInfo;
use tokio::net::TcpListener;
use tokio::sync::mpsc::Sender;
use tokio::task;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::{Mutex, mpsc};

use crate::frame_types::RfrpFrame;

pub type RoutingTable = Arc<Mutex<HashMap<u64, mpsc::Sender<Vec<u8>>>>>;

pub async fn handle_reg_frame(
    client_info: ClientInfo,
    tx_channel: Sender<RfrpFrame>,
    routing_table: RoutingTable,
) {
    let listener = match TcpListener::bind(format!("0.0.0.0:{}", client_info.get_bind_port())).await {
        Ok(listener) => {
            info!(
                "Proxy '{}' bound to port {}",
                client_info.get_name(),
                client_info.get_bind_port()
            );
            listener
        }
        Err(e) => {
            error!(
                "Failed to bind proxy '{}' on port {}: {}",
                client_info.get_name(),
                client_info.get_bind_port(),
                e
            );
            return;
        }
    };

    // Confirm registration to client
    let confirm = RfrpFrame::new_reg_frame(&client_info, true);
    if tx_channel.send(confirm).await.is_err() {
        error!("Failed to send registration confirmation, channel closed");
        return;
    }

    let mut next_conn_id: u64 = 0;

    loop {
        let (remote, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!(
                    "Proxy '{}' failed to accept connection: {}",
                    client_info.get_name(),
                    e
                );
                continue;
            }
        };

        let conn_id = next_conn_id;
        next_conn_id = next_conn_id.wrapping_add(1);

        info!(
            "Proxy '{}': accepted external conn {} from {}",
            client_info.get_name(),
            conn_id,
            peer
        );

        let (mut remote_read, mut remote_write) = remote.into_split();
        let client_info = client_info.clone();
        let tx_channel = tx_channel.clone();
        let routing = routing_table.clone();

        // Create a channel for writing data back to this external connection
        let (tx_to_remote, mut rx_to_remote) = mpsc::channel::<Vec<u8>>(64);

        // Register this connection in the routing table
        routing.lock().await.insert(conn_id, tx_to_remote);

        // Spawn read task: external user → client
        let tx = tx_channel.clone();
        let ci = client_info.clone();
        let cid = conn_id;
        let routing_cleanup = routing.clone();
        task::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match remote_read.read(&mut buf).await {
                    Ok(0) => {
                        info!(
                            "Proxy '{}' conn {}: external peer {} closed connection",
                            ci.get_name(),
                            cid,
                            peer
                        );
                        break;
                    }
                    Ok(n) => {
                        let frame = RfrpFrame::new_data_frame(&buf[..n], &ci, cid);
                        if tx.send(frame).await.is_err() {
                            error!(
                                "Proxy '{}' conn {}: failed to send data frame to client, channel closed",
                                ci.get_name(),
                                cid
                            );
                            break;
                        }
                    }
                    Err(e) => {
                        error!(
                            "Proxy '{}' conn {}: read error from external: {}",
                            ci.get_name(),
                            cid,
                            e
                        );
                        break;
                    }
                }
            }
            // Cleanup: remove from routing table on disconnect
            routing_cleanup.lock().await.remove(&cid);
            info!("Proxy '{}' conn {}: cleaned up from routing table", ci.get_name(), cid);
        });

        // Spawn write task: client → external user
        let ci = client_info.clone();
        let cid = conn_id;
        task::spawn(async move {
            while let Some(data) = rx_to_remote.recv().await {
                if let Err(e) = remote_write.write_all(&data).await {
                    error!(
                        "Proxy '{}' conn {}: write error to external: {}",
                        ci.get_name(),
                        cid,
                        e
                    );
                    break;
                }
            }
            info!(
                "Proxy '{}' conn {}: write task ended",
                ci.get_name(),
                cid
            );
        });
    }
}
