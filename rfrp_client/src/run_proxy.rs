use bytes::Bytes;
use bytes::BytesMut;
use dashmap::DashMap;
use log::{debug, error, info, warn};
use rfrp_config::config_info::base_info_ops::BaseInfoGetter;
use rfrp_config::config_info::base_types::{ClientInfo, ConfigInfo};
use rfrp_proto::coalesce::{self};
use rfrp_proto::crypto::Cipher;
use rfrp_proto::frame_types::RfrpFrame;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task;
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

/// Manages persistent connections to internal services, keyed by conn_id.
type InternalConnSender = mpsc::Sender<Bytes>;
/// Maps proxy name → its per-proxy internal connection map.
/// Uses DashMap for lock-free concurrent reads.
type ProxyInternalConnMap = Arc<DashMap<Arc<str>, Arc<DashMap<u64, InternalConnSender>>>>;

pub async fn run_proxy(remote: TcpStream, config: Arc<ConfigInfo>, cipher: Arc<Cipher>) {
    // Disable Nagle's algorithm for low-latency RDP forwarding
    if let Err(e) = remote.set_nodelay(true) {
        warn!("Failed to set TCP_NODELAY on server socket: {}", e);
    }

    let (reader, writer) = remote.into_split();

    let mut reader = FramedRead::new(reader, LengthDelimitedCodec::new());

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
            Some(Ok(resp_bytes)) => {
                let mut decode_buf = resp_bytes.to_vec();
                match RfrpFrame::decode_encrypted(&mut decode_buf, &cipher) {
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
                }
            }
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
    // Uses Arc<str> keys to match the frame's proxy_name type.
    let proxy_configs: dashmap::DashMap<Arc<str>, Arc<ClientInfo>> = config
        .get_client_proxy()
        .iter()
        .map(|ci| (Arc::from(ci.get_name()), Arc::new(ci.clone())))
        .collect();

    // Per-proxy internal connection maps so conn_ids don't collide
    let proxy_conns: ProxyInternalConnMap = Arc::new(DashMap::new());

    // Cache the last looked-up proxy name → conns mapping
    let mut cached_conns: Option<(Arc<str>, Arc<DashMap<u64, InternalConnSender>>)> = None;

    // Reusable buffer for decoding frames (avoids per-frame Vec allocation)
    let mut decode_buf: Vec<u8> = Vec::new();

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

        // Copy bytes into reusable decode buffer and decrypt in-place
        decode_buf.clear();
        decode_buf.extend_from_slice(&bytes);
        let frame = match RfrpFrame::decode_encrypted(&mut decode_buf, &cipher) {
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
                let proxy_name = &data_info.proxy_name;

                // Look up the ClientInfo from our pre-built config map.
                let client_info = match proxy_configs.get(proxy_name.as_ref()) {
                    Some(ci) => Arc::clone(ci.value()),
                    None => {
                        error!("Unknown proxy '{}' in data frame", proxy_name);
                        continue;
                    }
                };

                // Get or create the per-proxy connection map (with caching)
                let conns = match &cached_conns {
                    Some((name, map)) if name.as_ref() == proxy_name.as_ref() => Arc::clone(map),
                    _ => {
                        let map: Arc<DashMap<u64, InternalConnSender>> = proxy_conns
                            .entry(Arc::clone(proxy_name))
                            .or_insert_with(|| Arc::new(DashMap::new()))
                            .clone();
                        cached_conns = Some((Arc::clone(proxy_name), Arc::clone(&map)));
                        map
                    }
                };

                // Get or create a connection to the internal service.
                let sender =
                    get_or_create_internal_conn(&conns, conn_id, &client_info, &tx_to_server).await;

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
    conns: &Arc<DashMap<u64, InternalConnSender>>,
    conn_id: u64,
    client_info: &Arc<ClientInfo>,
    tx_to_server: &mpsc::Sender<RfrpFrame>,
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

    // Re-check: another task may have beaten us here
    if let Some(existing) = conns.get(&conn_id) {
        return Some(existing.value().clone());
    }
    conns.insert(conn_id, tx.clone());

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
            let _ = write_half.flush().await;
        }
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
        conns_cleanup.remove(&cid);
        info!(
            "Cleaned up internal connection for proxy '{}' conn {}",
            proxy_name, cid
        );
    });

    Some(tx)
}
