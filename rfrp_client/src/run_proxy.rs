use bytes::Bytes;
use bytes::BytesMut;
use log::{debug, error, info, warn};
use rfrp_config::config_info::base_info_ops::BaseInfoGetter;
use rfrp_config::config_info::base_types::{ClientInfo, ConfigInfo, P2pSignalType};
use rfrp_proto::coalesce::{self};
use rfrp_proto::crypto::{self, Cipher};
use rfrp_proto::frame_types::RfrpFrame;
use crate::p2p;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tokio::task;
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

/// Manages persistent connections to internal services, keyed by conn_id.
type InternalConnSender = mpsc::Sender<Bytes>;
type InternalConnMap = Arc<Mutex<HashMap<u64, InternalConnSender>>>;
/// Maps proxy name → its per-proxy internal connection map.
type ProxyInternalConnMap = Arc<Mutex<HashMap<String, InternalConnMap>>>;

pub async fn run_proxy(remote: TcpStream, config: ConfigInfo) {
    // Disable Nagle's algorithm for low-latency RDP forwarding
    if let Err(e) = remote.set_nodelay(true) {
        warn!("Failed to set TCP_NODELAY on server socket: {}", e);
    }

    let key = crypto::derive_key(config.get_server().get_auth_token());
    let cipher = Arc::new(Cipher::new(&key));

    let (reader, writer) = remote.into_split();

    let mut reader = FramedRead::new(reader, LengthDelimitedCodec::new());

    // Priority-based coalescing write task:
    // - Hi-priority: small frames (input events) sent immediately
    // - Lo-priority: large frames (screen data) buffered & coalesced
    let (tx_to_server, _write_handle) = coalesce::spawn_write_task(
        FramedWrite::new(writer, LengthDelimitedCodec::new()),
        Arc::clone(&cipher),
    );

    // Phase 1: Register all proxies
    for client_info in config.get_client_proxy() {
        debug!("Registering client proxy: {}", client_info.get_name());

        let reg_frame = RfrpFrame::Register(client_info.clone());

        if let Err(e) = tx_to_server.send(reg_frame).await {
            error!("Failed to send register frame: {}", e);
            return;
        }

        // Wait for registration confirmation from server
        match reader.next().await {
            Some(Ok(resp_bytes)) => match RfrpFrame::decode_encrypted(&resp_bytes, &cipher) {
                Ok(RfrpFrame::RegisterAck(resp)) => {
                    if resp.success {
                        info!(
                            "Successfully registered proxy '{}' on bind_port {}",
                            resp.client.get_name(),
                            resp.client.get_bind_port()
                        );
                    } else {
                        error!(
                            "Server rejected registration for proxy '{}'",
                            client_info.get_name()
                        );
                        return;
                    }
                }
                Ok(other) => {
                    error!(
                        "Unexpected frame during registration for '{}': {:?}",
                        client_info.get_name(),
                        other
                    );
                    return;
                }
                Err(e) => {
                    error!(
                        "Failed to decode registration response for '{}': {}",
                        client_info.get_name(),
                        e
                    );
                    return;
                }
            },
            Some(Err(e)) => {
                error!(
                    "Read error during registration for '{}': {}",
                    client_info.get_name(),
                    e
                );
                return;
            }
            None => {
                error!(
                    "Server closed connection during registration for '{}'",
                    client_info.get_name()
                );
                return;
            }
        }
    }

    info!("All proxies registered, entering data forwarding loop");

    // Pre-build proxy name → ClientInfo lookup map for Data frame routing.
    // Avoids carrying full ClientInfo in every Data frame on the wire.
    let proxy_configs: HashMap<String, Arc<ClientInfo>> = config
        .get_client_proxy()
        .iter()
        .map(|ci| (ci.get_name().to_string(), Arc::new(ci.clone())))
        .collect();

    // Spawn P2P connection tasks for p2p-type proxies
    let query_waiters = p2p::PeerQueryWaiters::default();
    let answer_waiters = p2p::AnswerWaiters::default();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let _shutdown_tx = shutdown_tx; // held to keep channel alive
    for client_info in config.get_client_proxy() {
        if client_info.get_proxy_con_type() == "p2p" {
            let peer_name = client_info.get_ip().to_string();
            let my_name = client_info.get_name().to_string();
            let bind_port = client_info.get_bind_port();
            let stun = client_info.get_p2p_stun_server().map(|s| s.to_string());
            info!(
                "P2P: spawning query task '{}' → '{}' (bind_port {})",
                my_name, peer_name, bind_port
            );
            task::spawn(p2p::query_and_connect(
                my_name, peer_name, bind_port, stun,
                Arc::clone(&cipher),
                tx_to_server.clone(),
                query_waiters.clone(), answer_waiters.clone(),
                shutdown_rx.clone(),
            ));
        }
    }

    // Per-proxy internal connection maps so conn_ids don't collide
    let proxy_conns: ProxyInternalConnMap = Arc::new(Mutex::new(HashMap::new()));

    // Phase 2: Main loop — forward data between server and internal services
    loop {
        let bytes = match reader.next().await {
            Some(Ok(bytes)) => bytes,
            Some(Err(e)) => {
                error!("Read error from server: {}", e);
                break;
            }
            None => {
                info!("Server closed connection");
                break;
            }
        };

        let frame = match RfrpFrame::decode_encrypted(&bytes, &cipher) {
            Ok(frame) => frame,
            Err(e) => {
                error!("Failed to decode frame: {}", e);
                continue;
            }
        };

        match frame {
            RfrpFrame::Data(data_info) => {
                let conn_id = data_info.conn_id;
                let data = data_info.data;
                let proxy_name = data_info.proxy_name.clone();

                // Look up the ClientInfo from our pre-built config map.
                // No Arc::clone here — get_or_create_internal_conn only needs &Arc.
                let client_info = match proxy_configs.get(&proxy_name) {
                    Some(ci) => ci,
                    None => {
                        error!("Unknown proxy '{}' in data frame", proxy_name);
                        continue;
                    }
                };

                // Get or create the per-proxy connection map
                let conns = {
                    let mut map = proxy_conns.lock().await;
                    map.entry(proxy_name)
                        .or_insert_with(|| Arc::new(Mutex::new(HashMap::new())))
                        .clone()
                };

                // Get or create a connection to the internal service.
                // tx_to_server is borrowed here — only cloned on the slow path.
                let sender =
                    get_or_create_internal_conn(&conns, conn_id, client_info, &tx_to_server).await;

                match sender {
                    Some(sender) => {
                        if let Err(e) = sender.send(data).await {
                            error!(
                                "Failed to forward data to internal service for conn {}: {}",
                                conn_id, e
                            );
                            // Clean up broken connection
                            conns.lock().await.remove(&conn_id);
                        }
                    }
                    None => {
                        error!(
                            "Could not establish connection to internal service {} for conn {}",
                            client_info.get_addr(),
                            conn_id
                        );
                    }
                }
            }
            RfrpFrame::Control(control_info) => {
                debug!("Received control frame: {:?}", control_info);
            }
            RfrpFrame::Register(client) => {
                warn!(
                    "Unexpected register frame for proxy '{}' in main loop",
                    client.get_name()
                );
            }
            RfrpFrame::RegisterAck(resp) => {
                warn!(
                    "Unexpected register ack for proxy '{}' in main loop",
                    resp.client.get_name()
                );
            }
            RfrpFrame::P2pSignal(signal) => {
                debug!(
                    "P2P signal {:?} from '{}'",
                    signal.signal_type, signal.from_client
                );
                match signal.signal_type {
                    P2pSignalType::PeerQuery => {
                        // Another peer is looking for us — respond with PeerFound
                        let reply = RfrpFrame::new_p2p_signal(
                            P2pSignalType::PeerFound,
                            &signal.to_client,     // from us
                            &signal.from_client,   // to them
                            signal.payload,         // echo payload
                        );
                        let _ = tx_to_server.send(reply).await;
                    }
                    P2pSignalType::PeerFound => {
                        // Server relayed a PeerFound to us — wake our query waiter
                        let mut w = query_waiters.lock().await;
                        if let Some(tx) = w.remove(&signal.from_client) {
                            let _ = tx.send(true);
                        }
                    }
                    P2pSignalType::Offer => {
                        let bind_port = {
                            config.get_client_proxy().iter()
                                .find(|c| c.get_name() == signal.to_client)
                                .map(|c| c.get_bind_port())
                                .unwrap_or(0)
                        };
                        let stun = config.get_client_proxy().iter()
                            .find(|c| c.get_name() == signal.to_client)
                            .and_then(|c| c.get_p2p_stun_server())
                            .map(|s| s.to_string());
                        if bind_port > 0 {
                            let sig = signal.clone();
                            task::spawn(p2p::handle_incoming_p2p_offer(
                                sig, bind_port, stun,
                                Arc::clone(&cipher),
                                tx_to_server.clone(), shutdown_rx.clone(),
                            ));
                        }
                    }
                    P2pSignalType::Answer => {
                        let mut w = answer_waiters.lock().await;
                        let addr_str = String::from_utf8_lossy(&signal.payload);
                        if let Ok(addr) = addr_str.parse() {
                            if let Some(tx) = w.remove(&signal.from_client) {
                                let _ = tx.send(addr);
                            }
                        }
                    }
                    _ => {
                        debug!("P2P: unhandled signal {:?}", signal.signal_type);
                    }
                }
            }
            RfrpFrame::P2pData(_) => {
                warn!("Unexpected P2pData frame (should be direct)");
            }
        }
    }

    // Abort the write task so it doesn't hang
    _write_handle.abort();
    info!("Client proxy session ended");
}

/// Get an existing internal connection for `conn_id`, or create a new one.
/// `tx_to_server` is borrowed to avoid an unnecessary clone on the fast path;
/// it is cloned only when spawning a new read task.
async fn get_or_create_internal_conn(
    conns: &InternalConnMap,
    conn_id: u64,
    client_info: &Arc<ClientInfo>,
    tx_to_server: &mpsc::Sender<RfrpFrame>,
) -> Option<mpsc::Sender<Bytes>> {
    // Fast path: connection already exists
    {
        let map = conns.lock().await;
        if let Some(sender) = map.get(&conn_id) {
            return Some(sender.clone());
        }
    }

    // Slow path: create a new connection to the internal service
    let addr = client_info.get_addr();
    info!(
        "Opening new connection to internal service {} for conn {}",
        addr, conn_id
    );

    let stream = match TcpStream::connect(&addr).await {
        Ok(stream) => {
            // Disable Nagle's algorithm for low-latency RDP forwarding
            if let Err(e) = stream.set_nodelay(true) {
                warn!("Failed to set TCP_NODELAY on internal socket: {}", e);
            }
            stream
        }
        Err(e) => {
            error!(
                "Failed to connect to internal service {} for conn {}: {}",
                addr, conn_id, e
            );
            return None;
        }
    };

    let (mut read_half, mut write_half) = stream.into_split();
    let (tx, mut rx) = mpsc::channel::<Bytes>(256);

    // Re-check under lock: another task may have beaten us here
    {
        let mut map = conns.lock().await;
        if let Some(existing) = map.get(&conn_id) {
            return Some(existing.clone());
        }
        map.insert(conn_id, tx.clone());
    }

    // Spawn write task: forwards data from server → internal service
    let ci_name = client_info.get_name().to_string();
    let cid = conn_id;
    task::spawn(async move {
        while let Some(data) = rx.recv().await {
            if let Err(e) = write_half.write_all(&data).await {
                error!(
                    "Failed to write to internal service for proxy '{}' conn {}: {}",
                    ci_name, cid, e
                );
                break;
            }
        }
        debug!("Write task for proxy '{}' conn {} ended", ci_name, cid);
    });

    // Spawn read task: reads responses from internal service → sends back to server
    let proxy_name = client_info.get_name().to_string();
    let cid = conn_id;
    let conns_cleanup = Arc::clone(conns);
    let tx_to_server = tx_to_server.clone(); // clone only on slow path
    task::spawn(async move {
        let mut buf = BytesMut::with_capacity(65536);
        loop {
            match read_half.read_buf(&mut buf).await {
                Ok(0) => {
                    info!(
                        "Internal service for proxy '{}' conn {} closed connection",
                        proxy_name, cid
                    );
                    break;
                }
                Ok(_) => {
                    let data = buf.split().freeze();
                    let frame = RfrpFrame::new_data_frame(data, &proxy_name, cid);
                    if tx_to_server.send(frame).await.is_err() {
                        error!(
                            "Failed to send response to server for proxy '{}' conn {}",
                            proxy_name, cid
                        );
                        break;
                    }
                }
                Err(e) => {
                    error!(
                        "Read error from internal service for proxy '{}' conn {}: {}",
                        proxy_name, cid, e
                    );
                    break;
                }
            }
        }
        // Clean up on disconnect
        conns_cleanup.lock().await.remove(&cid);
        info!(
            "Cleaned up internal connection for proxy '{}' conn {}",
            proxy_name, cid
        );
    });

    Some(tx)
}
