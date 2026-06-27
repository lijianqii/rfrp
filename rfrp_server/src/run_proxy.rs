use dashmap::DashMap;
use log::{debug, error, info, warn};
use rfrp_proto::coalesce;
use rfrp_proto::crypto::{self, Cipher};
use rfrp_proto::frame_handle::{RoutingTable, handle_reg_frame};
use rfrp_proto::frame_types::RfrpFrame;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::task::{self, JoinHandle};
use tokio::time::Instant;
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

/// Maps proxy_id → its per-connection routing table.
/// Uses DashMap for lock-free concurrent reads; writes (registration)
/// happen infrequently so the sharding overhead is negligible.
/// The numeric key (u32) avoids per-frame string hashing and comparison.
type ProxyRoutingMap = Arc<DashMap<u32, RoutingTable>>;

/// Maximum number of proxies a single client connection may register.
/// Prevents a single authenticated client from binding an unbounded
/// number of ports and exhausting server resources.
const MAX_PROXIES_PER_CLIENT: usize = 16;

/// If no frame is received from the client within this duration, the
/// connection is considered dead and will be closed. This catches
/// half-open connections (e.g. NAT timeout, network partition) where
/// TCP may not detect the failure for a long time. The client sends a
/// ping every `PING_INTERVAL` (defined in rfrp_client) so this should
/// be comfortably larger than that interval.
const KEEPALIVE_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(90);

pub async fn run_proxy(client: TcpStream, auth_token: String) {
    if let Err(e) = client.set_nodelay(true) {
        warn!("Failed to set TCP_NODELAY on client socket: {}", e);
    }

    let key = crypto::derive_key(&auth_token);
    let cipher = Arc::new(Cipher::new(&key));
    info!("Auth token configured, encryption enabled");

    let (reader, writer) = client.into_split();

    let mut reader = FramedRead::new(reader, LengthDelimitedCodec::new());

    let (tx_channel, _write_handle) = coalesce::spawn_write_task(
        FramedWrite::new(writer, LengthDelimitedCodec::new()),
        Arc::clone(&cipher),
    );

    // Per-proxy routing tables so conn_ids don't collide across proxies
    let proxy_routing: ProxyRoutingMap = Arc::new(DashMap::new());

    // Track proxy listener tasks so we can abort them on disconnect
    let mut proxy_tasks: Vec<JoinHandle<()>> = Vec::new();

    // Cache the last looked-up routing table to avoid DashMap lookup
    // on every Data frame.
    let mut cached_routing: Option<(u32, RoutingTable)> = None;

    // Next proxy_id to assign during registration
    let mut next_proxy_id: u32 = 0;

    // Reusable buffer and decompressor for the hot decode path.
    // The Decompress struct keeps its internal zlib state across frames,
    // avoiding a ~280KB allocation/deallocation on every frame.
    let mut decomp_buf = Vec::new();
    let mut decompress = flate2::Decompress::new(false);

    // Main read loop: receive frames from the client with keepalive timeout.
    // If no frame arrives within KEEPALIVE_TIMEOUT the connection is closed.
    loop {
        let deadline = Instant::now() + KEEPALIVE_TIMEOUT;
        let mut bytes = tokio::select! {
            biased;
            result = reader.next() => match result {
                Some(Ok(bytes)) => bytes,
                Some(Err(e)) => {
                    error!("Read error from client: {}", e);
                    break;
                }
                None => {
                    info!("Client closed connection");
                    break;
                }
            },
            _ = tokio::time::sleep_until(deadline) => {
                warn!("Keepalive timeout: no frame from client in {:?}, closing connection", KEEPALIVE_TIMEOUT);
                break;
            }
        };

        // Decrypt and decode in-place on the codec's buffer — no copy needed
        let frame = match RfrpFrame::decode_encrypted_bytes_mut(
            &mut bytes,
            &cipher,
            &mut decomp_buf,
            &mut decompress,
        ) {
            Ok(frame) => frame,
            Err(e) => {
                error!("Failed to decode frame from client: {}", e);
                continue;
            }
        };

        match frame {
            RfrpFrame::Register(client_info) => {
                // Enforce per-client proxy limit to prevent resource exhaustion
                if proxy_tasks.len() >= MAX_PROXIES_PER_CLIENT {
                    error!(
                        "Client exceeded max proxy limit ({}), rejecting proxy '{}'",
                        MAX_PROXIES_PER_CLIENT,
                        client_info.get_name()
                    );
                    // Notify client of rejection
                    let reject = RfrpFrame::new_reg_ack_frame(&client_info, false, 0);
                    let _ = tx_channel.send(reject).await;
                    continue;
                }

                info!("Client registered proxy: {:?}", client_info.get_name());
                let proxy_id = next_proxy_id;
                next_proxy_id = next_proxy_id.wrapping_add(1);
                let routing: RoutingTable = Arc::new(DashMap::new());
                proxy_routing.insert(proxy_id, Arc::clone(&routing));

                // handle_reg_frame binds the port and sends the ACK:
                // success=true only if the listener bound successfully,
                // success=false (with proxy_id=0) on bind failure.
                let tx = tx_channel.clone();
                let handle = task::spawn(async move {
                    handle_reg_frame(client_info, tx, routing, proxy_id).await;
                });
                proxy_tasks.push(handle);
            }
            RfrpFrame::Control(control_info) => {
                if control_info.command == "ping" {
                    debug!("Received ping from client, replying pong");
                    let pong = RfrpFrame::new_pong_frame();
                    if let Err(e) = tx_channel.send(pong).await {
                        error!("Failed to send pong: {}", e);
                        break;
                    }
                } else if control_info.command == "pong" {
                    // Server doesn't initiate pings, so a pong is unexpected.
                    debug!("Received unexpected pong from client");
                } else {
                    info!("Control info: {:?}", control_info);
                }
            }
            RfrpFrame::RegisterAck(_) => {
                warn!("Unexpected RegisterAck frame received on server");
            }
            RfrpFrame::Data(data_info) => {
                let proxy_id = data_info.proxy_id;

                // Use cached routing table if proxy_id matches, otherwise look up in DashMap
                let routing = match &cached_routing {
                    Some((id, rt)) if *id == proxy_id => Some(Arc::clone(rt)),
                    _ => {
                        let rt = proxy_routing.get(&proxy_id).map(|r| Arc::clone(r.value()));
                        if let Some(ref rt) = rt {
                            cached_routing = Some((proxy_id, Arc::clone(rt)));
                        }
                        rt
                    }
                };

                // Look up conn_id in the proxy's routing table
                let sender = match routing {
                    Some(rt) => rt.get(&data_info.conn_id).map(|r| r.value().clone()),
                    None => None,
                };
                match sender {
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
                            "No route found for conn {} (proxy_id {}), connection may have been closed",
                            data_info.conn_id, proxy_id
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
    // Clean up routing table entries
    proxy_routing.clear();
    info!("Server proxy session ended");
}
