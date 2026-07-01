use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use log::{error, info, warn};
use rfrp_config::config_info::base_types::ClientInfo;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::sync::mpsc;
use tokio::task;

use crate::frame_types::RfrpFrame;

use tokio::sync::mpsc::Sender;

type ConnSender = mpsc::Sender<Bytes>;
/// Lock-free routing table: maps conn_id → channel sender.
/// Uses DashMap for concurrent access without explicit locking.
pub type RoutingTable = Arc<DashMap<u64, ConnSender>>;

/// Maximum number of concurrent external connections per proxy.
/// External users connecting to the exposed proxy port do not need
/// any token — this cap prevents unauthenticated resource exhaustion
/// via the exposed ports.
const MAX_CONCURRENT_EXTERNAL_CONNS: usize = 1024;

pub async fn handle_reg_frame(
    client_info: ClientInfo,
    tx_channel: Sender<RfrpFrame>,
    routing_table: RoutingTable,
    proxy_id: u32,
) {
    let client_info = Arc::new(client_info);
    let proxy_name: Arc<str> = Arc::from(client_info.get_name());

    let bind_port = client_info.get_bind_port();
    if bind_port < 1024 {
        error!(
            "Proxy '{}': rejected bind_port {} (privileged ports < 1024 not allowed)",
            proxy_name, bind_port
        );
        let reject = RfrpFrame::new_reg_ack_frame(&client_info, false, 0);
        let _ = tx_channel.send(reject).await;
        return;
    }

    let listener = match TcpListener::bind(format!("0.0.0.0:{}", bind_port)).await
    {
        Ok(listener) => {
            info!(
                "Proxy '{}' (id {}) bound to port {}",
                proxy_name,
                proxy_id,
                client_info.get_bind_port()
            );
            // Port bound successfully — send success ACK with the assigned proxy_id.
            // Only now do we confirm registration, so the client knows the proxy
            // is actually reachable.
            let ack = RfrpFrame::new_reg_ack_frame(&client_info, true, proxy_id);
            if tx_channel.send(ack).await.is_err() {
                error!("Failed to send registration confirmation, channel closed");
            }
            listener
        }
        Err(e) => {
            error!(
                "Failed to bind proxy '{}' (id {}) on port {}: {}",
                proxy_name,
                proxy_id,
                client_info.get_bind_port(),
                e
            );
            // Notify client that registration failed so it doesn't route
            // data to a non-existent proxy.
            let reject = RfrpFrame::new_reg_ack_frame(&client_info, false, 0);
            let _ = tx_channel.send(reject).await;
            return;
        }
    };

    let mut next_conn_id: u64 = 0;

    // Cap concurrent external connections to prevent unauthenticated
    // resource exhaustion via the exposed proxy port.
    let ext_conn_limit = Arc::new(Semaphore::new(MAX_CONCURRENT_EXTERNAL_CONNS));

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
            "Proxy '{}' (id {}): accepted external conn {} from {}",
            proxy_name, proxy_id, conn_id, peer
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
        routing.insert(conn_id, tx_to_remote);

        // Acquire a permit for this external connection. The read task holds
        // the permit for the connection lifetime; when the peer disconnects
        // the read task exits, the permit is released, and the write task
        // drains shortly after (its rx channel closes).
        let conn_permit = match ext_conn_limit.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => {
                warn!(
                    "Proxy '{}' (id {}): connection limit semaphore closed, rejecting conn {}",
                    proxy_name, proxy_id, conn_id
                );
                routing.remove(&conn_id);
                continue;
            }
        };

        // Spawn read task: external user → client
        let tx = tx_channel.clone();
        let proxy_name_read = Arc::clone(&proxy_name);
        let cid = conn_id;
        let routing_cleanup = routing.clone();
        task::spawn(async move {
            let _permit = conn_permit; // hold permit for task lifetime
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
                        let frame = RfrpFrame::new_data_frame(data, proxy_id, cid);
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
            routing_cleanup.remove(&cid);
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
                // Only flush when the channel is drained: lets BufWriter
                // coalesce back-to-back frames into a single syscall while
                // still keeping latency low when there's no queued data.
                if rx_to_remote.is_empty() {
                    let _ = remote_write.flush().await;
                }
            }
            // Ensure any buffered data is flushed before the task exits
            let _ = remote_write.flush().await;
            info!(
                "Proxy '{}' conn {}: write task ended",
                proxy_name_write, cid
            );
        });
    }
}
