use bytes::Bytes;
use bytes::BytesMut;
use dashmap::DashMap;
use log::{debug, error, info, warn};
use rfrp_config::config_info::base_info_ops::BaseInfoGetter;
use rfrp_config::config_info::base_types::{ClientInfo, ConfigInfo};
use rfrp_proto::coalesce::{self};
use rfrp_proto::frame_types::RfrpFrame;
use rfrp_proto::handshake;
use rfrp_proto::make_length_delimited_codec;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task;
use tokio::time::Instant;
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, FramedWrite};

/// Manages persistent connections to internal services, keyed by conn_id.
type InternalConnSender = mpsc::Sender<Bytes>;
/// Maps proxy_id → its per-proxy internal connection map.
/// Uses DashMap for lock-free concurrent reads.
type ProxyInternalConnMap = Arc<DashMap<u32, Arc<DashMap<u64, InternalConnSender>>>>;

/// Interval at which the client sends heartbeat ping frames to the server.
const PING_INTERVAL: tokio::time::Duration = tokio::time::Duration::from_secs(30);

/// If no frame (data or pong) is received from the server within this
/// duration, the connection is considered dead and the client will
/// reconnect. This is 3× the ping interval to tolerate missed pings
/// and network jitter.
const KEEPALIVE_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(90);

pub async fn run_proxy(remote: TcpStream, config: Arc<ConfigInfo>) {
    if let Err(e) = remote.set_nodelay(true) {
        warn!("Failed to set TCP_NODELAY on server socket: {}", e);
    }

    let auth_token = config.get_server().get_auth_token();
    let (remote, cipher) = match handshake::client_handshake(remote, auth_token).await {
        Ok((socket, cipher)) => (socket, cipher),
        Err(e) => {
            error!("Handshake failed: {}", e);
            return;
        }
    };

    let (reader, writer) = remote.into_split();

    let mut reader = FramedRead::new(reader, make_length_delimited_codec());

    let (tx_to_server, _write_handle) = coalesce::spawn_write_task(
        FramedWrite::new(writer, make_length_delimited_codec()),
        Arc::clone(&cipher),
    );

    // Reusable buffer and decompressor for the hot decode path.
    // The Decompress struct keeps its internal zlib state across frames,
    // avoiding a ~280KB allocation/deallocation on every frame.
    let mut decomp_buf = Vec::new();
    let mut decompress = flate2::Decompress::new(false);

    // Phase 1: Register all proxies and record the proxy_id assigned by the server.
    // Each registration response must arrive within KEEPALIVE_TIMEOUT, otherwise
    // the connection is treated as dead.
    let proxy_configs: dashmap::DashMap<u32, Arc<ClientInfo>> = dashmap::DashMap::new();
    for client_info in config.get_client_proxy() {
        debug!("Registering client proxy: {}", client_info.get_name());

        let reg_frame = RfrpFrame::Register(client_info.clone());

        if let Err(e) = tx_to_server.send(reg_frame).await {
            error!("Failed to send register frame: {}", e);
            return;
        }

        // Wait for registration confirmation from server (with keepalive timeout)
        let next_result = tokio::time::timeout(KEEPALIVE_TIMEOUT, reader.next()).await;
        match next_result {
            Ok(Some(Ok(resp_bytes))) => {
                let mut resp_buf = resp_bytes;
                match RfrpFrame::decode_encrypted_bytes_mut(
                    &mut resp_buf,
                    &cipher,
                    &mut decomp_buf,
                    &mut decompress,
                ) {
                    Ok(RfrpFrame::RegisterAck(resp)) => {
                        if resp.success {
                            info!(
                                "Successfully registered proxy '{}' (id {}) on bind_port {}",
                                resp.client.get_name(),
                                resp.proxy_id,
                                resp.client.get_bind_port()
                            );
                            proxy_configs.insert(resp.proxy_id, Arc::new(client_info.clone()));
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
                }
            }
            Ok(Some(Err(e))) => {
                error!(
                    "Read error during registration for '{}': {}",
                    client_info.get_name(),
                    e
                );
                return;
            }
            Ok(None) => {
                error!(
                    "Server closed connection during registration for '{}'",
                    client_info.get_name()
                );
                return;
            }
            Err(_) => {
                error!(
                    "Keepalive timeout during registration for '{}': no response in {:?}",
                    client_info.get_name(),
                    KEEPALIVE_TIMEOUT
                );
                return;
            }
        }
    }

    info!("All proxies registered, entering data forwarding loop");

    // Per-proxy internal connection maps so conn_ids don't collide
    let proxy_conns: ProxyInternalConnMap = Arc::new(DashMap::new());

    // Cache the last looked-up proxy_id → conns mapping
    let mut cached_conns: Option<(u32, Arc<DashMap<u64, InternalConnSender>>)> = None;

    // Spawn a heartbeat task that sends a ping frame every PING_INTERVAL.
    // The task exits when the write channel (tx_to_server) is closed,
    // which happens when the main loop breaks on disconnect.
    //
    // MissedTickBehavior::Delay ensures that if the runtime is busy and
    // a tick is missed, the next ping fires one full interval later
    // rather than bursting multiple pings back-to-back.
    let ping_tx = tx_to_server.clone();
    let ping_handle = task::spawn(async move {
        let mut interval = tokio::time::interval(PING_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await; // skip the immediate first tick
        loop {
            interval.tick().await;
            if ping_tx.send(RfrpFrame::new_ping_frame()).await.is_err() {
                // Channel closed — main loop has ended, stop pinging
                break;
            }
            debug!("Sent heartbeat ping to server");
        }
    });

    // Phase 2: Main loop — forward data between server and internal services.
    // Uses tokio::select! to race the read against a keepalive timeout.
    // Any frame received (data or pong) resets the timeout.
    loop {
        let deadline = Instant::now() + KEEPALIVE_TIMEOUT;
        let mut bytes = tokio::select! {
            biased;
            result = reader.next() => match result {
                Some(Ok(bytes)) => bytes,
                Some(Err(e)) => {
                    error!("Read error from server: {}", e);
                    break;
                }
                None => {
                    info!("Server closed connection");
                    break;
                }
            },
            _ = tokio::time::sleep_until(deadline) => {
                warn!("Keepalive timeout: no frame from server in {:?}, reconnecting", KEEPALIVE_TIMEOUT);
                break;
            }
        };

        // Decrypt and decode in-place on the codec's BytesMut — no copy needed
        let frame = match RfrpFrame::decode_encrypted_bytes_mut(
            &mut bytes,
            &cipher,
            &mut decomp_buf,
            &mut decompress,
        ) {
            Ok(frame) => frame,
            Err(e) => {
                error!("Failed to decode frame: {}, disconnecting", e);
                break;
            }
        };

        match frame {
            RfrpFrame::Data(data_info) => {
                let conn_id = data_info.conn_id;
                let data = data_info.data;
                let proxy_id = data_info.proxy_id;

                // Look up the ClientInfo from our pre-built config map.
                let client_info = match proxy_configs.get(&proxy_id) {
                    Some(ci) => Arc::clone(ci.value()),
                    None => {
                        error!("Unknown proxy_id {} in data frame", proxy_id);
                        continue;
                    }
                };

                // Get or create the per-proxy connection map (with caching)
                let conns = match &cached_conns {
                    Some((id, map)) if *id == proxy_id => Arc::clone(map),
                    _ => {
                        let map: Arc<DashMap<u64, InternalConnSender>> = proxy_conns
                            .entry(proxy_id)
                            .or_insert_with(|| Arc::new(DashMap::new()))
                            .clone();
                        cached_conns = Some((proxy_id, Arc::clone(&map)));
                        map
                    }
                };

                // Get or create a connection to the internal service.
                let sender = get_or_create_internal_conn(
                    &conns,
                    conn_id,
                    &client_info,
                    &tx_to_server,
                    proxy_id,
                )
                .await;

                match sender {
                    Some(sender) => {
                        if let Err(e) = sender.send(data).await {
                            error!(
                                "Failed to forward data to internal service for conn {}: {}",
                                conn_id, e
                            );
                            // Clean up broken connection
                            conns.remove(&conn_id);
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
                if control_info.command == "pong" {
                    debug!("Received heartbeat pong from server");
                } else {
                    debug!("Received control frame: {:?}", control_info);
                }
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
        }
    }

    // Abort the write task so it doesn't hang
    _write_handle.abort();
    // Abort the heartbeat task
    ping_handle.abort();
    info!("Client proxy session ended");
}

/// Get an existing internal connection for `conn_id`, or create a new one.
/// `tx_to_server` is borrowed to avoid an unnecessary clone on the fast path;
/// it is cloned only when spawning a new read task.
async fn get_or_create_internal_conn(
    conns: &Arc<DashMap<u64, InternalConnSender>>,
    conn_id: u64,
    client_info: &Arc<ClientInfo>,
    tx_to_server: &mpsc::Sender<RfrpFrame>,
    proxy_id: u32,
) -> Option<mpsc::Sender<Bytes>> {
    // Fast path: connection already exists (lock-free DashMap read)
    if let Some(sender) = conns.get(&conn_id) {
        return Some(sender.value().clone());
    }

    // Slow path: create a new connection to the internal service
    let addr = client_info.get_addr();
    info!(
        "Opening new connection to internal service {} for conn {}",
        addr, conn_id
    );

    let stream = match TcpStream::connect(addr).await {
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

    let (mut read_half, write_half) = stream.into_split();
    let (tx, mut rx) = mpsc::channel::<Bytes>(256);

    // Atomically insert — if another task beat us here, use theirs
    let tx = match conns.entry(conn_id) {
        dashmap::mapref::entry::Entry::Occupied(existing) => {
            return Some(existing.get().clone());
        }
        dashmap::mapref::entry::Entry::Vacant(vacant) => {
            let tx = tx.clone();
            vacant.insert(tx.clone());
            tx
        }
    };

    // Spawn write task: forwards data from server → internal service
    // Wraps in BufWriter to reduce syscall overhead
    let ci_name: Arc<str> = Arc::from(client_info.get_name());
    let cid = conn_id;
    task::spawn(async move {
        let mut write_half = BufWriter::new(write_half);
        while let Some(data) = rx.recv().await {
            if let Err(e) = write_half.write_all(&data).await {
                error!(
                    "Failed to write to internal service for proxy '{}' conn {}: {}",
                    ci_name, cid, e
                );
                break;
            }
            // Only flush when the channel is drained: lets BufWriter
            // coalesce back-to-back frames into a single syscall while
            // still keeping latency low when there's no queued data.
            if rx.is_empty() {
                let _ = write_half.flush().await;
            }
        }
        // Ensure any buffered data is flushed before the task exits
        let _ = write_half.flush().await;
        debug!("Write task for proxy '{}' conn {} ended", ci_name, cid);
    });

    // Spawn read task: reads responses from internal service → sends back to server
    let proxy_name: Arc<str> = Arc::from(client_info.get_name());
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
                    let frame = RfrpFrame::new_data_frame(data, proxy_id, cid);
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
        conns_cleanup.remove(&cid);
        info!(
            "Cleaned up internal connection for proxy '{}' conn {}",
            proxy_name, cid
        );
    });

    Some(tx)
}
