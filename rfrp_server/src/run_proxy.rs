use bytes::BytesMut;
use dashmap::DashMap;
use log::{error, info, warn};
use rfrp_proto::coalesce;
use rfrp_proto::crypto::{self, Cipher};
use rfrp_proto::frame_handle::{RoutingTable, handle_reg_frame};
use rfrp_proto::frame_types::RfrpFrame;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::task::{self, JoinHandle};
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

/// Maps proxy name → its per-connection routing table.
/// Uses DashMap for lock-free concurrent reads; writes (registration)
/// happen infrequently so the sharding overhead is negligible.
type ProxyRoutingMap = Arc<DashMap<Arc<str>, RoutingTable>>;

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
    let mut cached_routing: Option<(Arc<str>, RoutingTable)> = None;

    // Reusable buffer for decompression output
    let mut decomp_buf = BytesMut::new();

    // Main read loop: receive frames from the client
    loop {
        let mut bytes = match reader.next().await {
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

        // Decrypt and decode in-place on the codec's BytesMut — no copy needed
        let frame = match RfrpFrame::decode_encrypted_bytes_mut(&mut bytes, &cipher, &mut decomp_buf) {
            Ok(frame) => frame,
            Err(e) => {
                error!("Failed to decode frame from client: {}", e);
                continue;
            }
        };

        match frame {
            RfrpFrame::Register(client_info) => {
                info!("Client registered proxy: {:?}", client_info.get_name());
                let name: Arc<str> = Arc::from(client_info.get_name());
                let routing: RoutingTable = Arc::new(DashMap::new());
                proxy_routing.insert(Arc::clone(&name), Arc::clone(&routing));
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
                let proxy_name = &data_info.proxy_name;

                // Use cached routing table if proxy name matches, otherwise look up in DashMap
                let routing = match &cached_routing {
                    Some((name, rt)) if name.as_ref() == proxy_name.as_ref() => {
                        Some(Arc::clone(rt))
                    }
                    _ => {
                        let rt = proxy_routing
                            .get(proxy_name.as_ref())
                            .map(|r| Arc::clone(r.value()));
                        if let Some(ref rt) = rt {
                            cached_routing = Some((Arc::clone(proxy_name), Arc::clone(rt)));
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
                            "No route found for conn {} (proxy '{}'), connection may have been closed",
                            data_info.conn_id, proxy_name
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
