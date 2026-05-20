use log::{error, info, warn};
use rfrp_proto::coalesce;
use rfrp_proto::crypto::{self, Cipher};
use rfrp_proto::frame_handle::{RoutingTable, handle_reg_frame};
use rfrp_proto::frame_types::RfrpFrame;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::task::{self, JoinHandle};
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

/// Maps proxy name → its per-connection routing table.
type ProxyRoutingMap = Arc<Mutex<HashMap<String, RoutingTable>>>;

pub async fn run_proxy(client: TcpStream, auth_token: String) {
    if let Err(e) = client.set_nodelay(true) {
        warn!("Failed to set TCP_NODELAY on client socket: {}", e);
    }

    let key = crypto::derive_key(&auth_token);
    let cipher = Arc::new(Cipher::new(&key));
    info!("Auth token configured, encryption enabled");

    let (reader, writer) = client.into_split();

    let mut reader = FramedRead::new(reader, LengthDelimitedCodec::new());

    // Priority-based coalescing write task:
    // - Hi-priority: small frames (input events) sent immediately
    // - Lo-priority: large frames (screen data) buffered & coalesced
    let (tx_channel, _write_handle) = coalesce::spawn_write_task(
        FramedWrite::new(writer, LengthDelimitedCodec::new()),
        Arc::clone(&cipher),
    );

    // Per-proxy routing tables so conn_ids don't collide across proxies
    let proxy_routing: ProxyRoutingMap = Arc::new(Mutex::new(HashMap::new()));

    // Track proxy listener tasks so we can abort them on disconnect
    let mut proxy_tasks: Vec<JoinHandle<()>> = Vec::new();

    // Cache the last looked-up routing table to avoid locking proxy_routing
    // on every Data frame. The RoutingTable Arc never changes once registered.
    let mut cached_routing: Option<(String, RoutingTable)> = None;

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

        let frame = match RfrpFrame::decode_encrypted(&bytes, &cipher) {
            Ok(frame) => frame,
            Err(e) => {
                error!("Failed to decode frame from client: {}", e);
                continue;
            }
        };

        match frame {
            RfrpFrame::Register(client_info) => {
                info!("Client registered proxy: {:?}", client_info.get_name());
                let name = client_info.get_name().to_string();
                // Each proxy gets its own routing table so conn_ids don't collide
                let routing: RoutingTable = Arc::new(Mutex::new(HashMap::new()));
                proxy_routing
                    .lock()
                    .await
                    .insert(name.clone(), Arc::clone(&routing));
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
                // Use cached routing table if proxy name matches, otherwise lock
                let routing = match &cached_routing {
                    Some((name, rt)) if name == &data_info.proxy_name => Some(rt.clone()),
                    _ => {
                        let rt = {
                            let routing_map = proxy_routing.lock().await;
                            routing_map.get(&data_info.proxy_name).cloned()
                        };
                        if let Some(ref rt) = rt {
                            cached_routing = Some((data_info.proxy_name.clone(), rt.clone()));
                        }
                        rt
                    }
                };
                // Look up conn_id in the proxy's routing table
                let sender = match routing {
                    Some(rt) => {
                        let table = rt.lock().await;
                        table.get(&data_info.conn_id).cloned()
                    }
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
                            data_info.conn_id, data_info.proxy_name
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
    proxy_routing.lock().await.clear();
    info!("Server proxy session ended");
}
