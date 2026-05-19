//! P2P proxy module: server-relayed signaling + libudx reliable UDP transport.
//! Activated when proxy_con_type == "p2p" in the proxy config.
//!
//! Flow:
//!   Client A ──PeerQuery──▶ Server ──PeerQuery──▶ Client B
//!   Client A ◀─PeerFound──  Server  ◀─PeerFound── Client B
//!   Client A ──Offer──────▶ Server ──Offer──────▶ Client B
//!   Client A ◀─Answer─────  Server  ◀─Answer───── Client B
//!   Client A ════════ UDX reliable stream ════════▶ Client B

use libudx::{UdxRuntime, UdxStream};
use log::{debug, error, info, warn};
use rfrp_config::config_info::base_types::{P2pSignalInfo, P2pSignalType};
use rfrp_proto::crypto::Cipher;
use rfrp_proto::frame_types::RfrpFrame;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot, watch, Mutex};
use tokio::task;
use tokio::time::{self, Duration};

// ── Constants ───────────────────────────────────────────────────────────────

const PEER_QUERY_TIMEOUT_SECS: u64 = 10;
const PEER_QUERY_RETRY_SECS: u64 = 5;
const ANSWER_TIMEOUT_SECS: u64 = 15;

// ── STUN ────────────────────────────────────────────────────────────────────

/// Query a STUN server for our public UDP address.
async fn stun_query(local_addr: SocketAddr, stun_server: &str) -> SocketAddr {
    // Resolve hostname if needed
    let stun_addr: SocketAddr = match stun_server.parse() {
        Ok(a) => a,
        Err(_) => {
            // Try DNS resolution: split host:port
            if let Some((host, port)) = stun_server.rsplit_once(':') {
                let port: u16 = match port.parse() {
                    Ok(p) => p,
                    Err(_) => {
                        warn!("P2P: invalid STUN port in '{}'", stun_server);
                        return local_addr;
                    }
                };
                match tokio::net::lookup_host((host, port)).await {
                    Ok(mut addrs) => {
                        if let Some(addr) = addrs.next() {
                            addr
                        } else {
                            warn!("P2P: STUN DNS resolved no addresses for '{}'", host);
                            return local_addr;
                        }
                    }
                    Err(e) => {
                        warn!("P2P: STUN DNS lookup failed for '{}': {}", host, e);
                        return local_addr;
                    }
                }
            } else {
                warn!("P2P: invalid STUN server '{}'", stun_server);
                return local_addr;
            }
        }
    };

    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            warn!("P2P: STUN bind failed: {}", e);
            return local_addr;
        }
    };

    // STUN Binding Request: type=0x0001, length=0, magic=0x2112A442, tid=zeros
    let request: [u8; 20] = [
        0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    if sock.send_to(&request, stun_addr).await.is_err() {
        warn!("P2P: STUN send failed");
        return local_addr;
    }

    let mut buf = [0u8; 64];
    let n = match tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => n,
        _ => {
            warn!("P2P: STUN response timeout");
            return local_addr;
        }
    };

    if n < 20 {
        return local_addr;
    }

    // Parse XOR-MAPPED-ADDRESS (type 0x0020) from STUN response
    let mut pos = 20;
    while pos + 4 <= n {
        let attr_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let attr_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;
        if attr_type == 0x0020 && attr_len >= 8 && pos + attr_len <= n {
            // Skip family (1 byte) and x-port
            let xport = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
            let port = xport ^ 0x2112;
            let xip = u32::from_be_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]);
            let ip = std::net::Ipv4Addr::from(xip ^ 0x2112A442);
            let addr = SocketAddr::new(std::net::IpAddr::V4(ip), port);
            info!("P2P: STUN mapped address: {} (local: {})", addr, local_addr);
            return addr;
        }
        pos += attr_len;
        // Align to 4 bytes
        pos = (pos + 3) & !3;
    }

    warn!("P2P: no XOR-MAPPED-ADDRESS in STUN response");
    local_addr
}

// ── Types ───────────────────────────────────────────────────────────────────

pub type PeerQueryWaiters = Arc<Mutex<HashMap<String, oneshot::Sender<bool>>>>;
pub type AnswerWaiters = Arc<Mutex<HashMap<String, oneshot::Sender<SocketAddr>>>>;
type ShutdownRx = watch::Receiver<bool>;

// ── Public API ──────────────────────────────────────────────────────────────

/// Continuously query for a peer and establish a P2P connection when found.
pub async fn query_and_connect(
    my_name: String,
    peer_name: String,
    bind_port: u16,
    stun_server: Option<String>,
    cipher: Arc<Cipher>,
    tx_to_server: mpsc::Sender<RfrpFrame>,
    query_waiters: PeerQueryWaiters,
    answer_waiters: AnswerWaiters,
    mut shutdown_rx: ShutdownRx,
) {
    let my_name = my_name;
    let peer_name = peer_name;
    info!(
        "P2P '{}': starting peer query loop for '{}'",
        my_name, peer_name
    );

    loop {
        let (tx, mut rx) = oneshot::channel();
        {
            query_waiters
                .lock()
                .await
                .insert(peer_name.clone(), tx);
        }

        let query = RfrpFrame::new_p2p_signal(
            P2pSignalType::PeerQuery,
            &my_name,
            &peer_name,
            vec![],
        );
        if tx_to_server.send(query).await.is_err() {
            error!("P2P '{}': channel to server closed", my_name);
            return;
        }

        tokio::select! {
            _ = shutdown_rx.changed() => {
                info!("P2P '{}': shutdown", my_name);
                return;
            }
            result = time::timeout(
                Duration::from_secs(PEER_QUERY_TIMEOUT_SECS),
                &mut rx,
            ) => {
                match result {
                    Ok(Ok(true)) => {
                        info!("P2P '{}': peer '{}' online, initiating", my_name, peer_name);
                        match initiate_p2p_connection(
                            &my_name, &peer_name, bind_port,
                            stun_server.clone(),
                            cipher.clone(),
                            tx_to_server.clone(), answer_waiters.clone(),
                            shutdown_rx.clone(),
                        ).await {
                            Ok(()) => return,
                            Err(e) => error!("P2P '{}': {} — retrying", my_name, e),
                        }
                    }
                    Ok(Ok(false)) => debug!("P2P '{}': peer not online", my_name),
                    _ => debug!("P2P '{}': PeerQuery timed out", my_name),
                }
            }
        }

        tokio::select! {
            _ = shutdown_rx.changed() => {
                info!("P2P '{}': shutdown", my_name);
                return;
            }
            _ = time::sleep(Duration::from_secs(PEER_QUERY_RETRY_SECS)) => {}
        }
    }
}

/// Initiate a P2P connection: bind UDX, send Offer, wait for Answer, connect.
pub async fn initiate_p2p_connection(
    my_name: &str,
    peer_name: &str,
    bind_port: u16,
    stun_server: Option<String>,
    cipher: Arc<Cipher>,
    tx_to_server: mpsc::Sender<RfrpFrame>,
    answer_waiters: AnswerWaiters,
    mut shutdown_rx: ShutdownRx,
) -> Result<(), String> {
    // Create UDX runtime and bind socket
    let runtime = UdxRuntime::new().map_err(|e| format!("UDX runtime: {}", e))?;
    let socket = runtime
        .create_socket()
        .await
        .map_err(|e| format!("UDX socket: {}", e))?;
    socket
        .bind("0.0.0.0:0".parse().unwrap())
        .await
        .map_err(|e| format!("UDX bind: {}", e))?;
    let local_addr = socket
        .local_addr()
        .await
        .map_err(|e| format!("UDX local_addr: {}", e))?;

    // Discover public address via STUN (falls back to local if no STUN server)
    let public_addr = if let Some(ref stun) = stun_server {
        stun_query(local_addr, stun).await
    } else {
        local_addr
    };
    info!(
        "P2P initiator '{}': UDX bound at {}",
        my_name, local_addr
    );

    // Send Offer with our public UDP address
    let payload = public_addr.to_string().into_bytes();
    let offer = RfrpFrame::new_p2p_signal(
        P2pSignalType::Offer,
        my_name,
        peer_name,
        payload,
    );
    tx_to_server
        .send(offer)
        .await
        .map_err(|e| format!("send Offer: {}", e))?;
    info!("P2P initiator '{}': Offer sent", my_name);

    // Wait for Answer
    let (tx, mut rx) = oneshot::channel();
    {
        answer_waiters
            .lock()
            .await
            .insert(peer_name.to_string(), tx);
    }

    let peer_addr = tokio::select! {
        _ = shutdown_rx.changed() => return Err("shutdown".into()),
        result = time::timeout(Duration::from_secs(ANSWER_TIMEOUT_SECS), &mut rx) => {
            match result {
                Ok(Ok(addr)) => addr,
                _ => return Err("Answer timeout".into()),
            }
        }
    };

    info!(
        "P2P initiator '{}': got Answer, peer at {}",
        my_name, peer_addr
    );

    // Connect via UDX
    let stream = runtime
        .create_stream(1)
        .await
        .map_err(|e| format!("create stream: {}", e))?;
    stream
        .connect(&socket, 1, peer_addr)
        .await
        .map_err(|e| format!("UDX connect: {}", e))?;

    info!(
        "P2P initiator '{}': UDX stream connected to {}",
        my_name, peer_addr
    );

    // Forward between UDX stream and internal TCP service
    forward_udx_to_tcp(stream, bind_port, cipher, my_name, peer_name, shutdown_rx).await;
    Ok(())
}

/// Handle an incoming P2P connection from another peer.
pub async fn handle_incoming_p2p_offer(
    signal: P2pSignalInfo,
    bind_port: u16,
    stun_server: Option<String>,
    cipher: Arc<Cipher>,
    tx_to_server: mpsc::Sender<RfrpFrame>,
    shutdown_rx: ShutdownRx,
) {
    let my_name = signal.to_client.clone();
    let peer_name = signal.from_client.clone();

    // Parse peer's address from signal payload
    let peer_addr_str = String::from_utf8_lossy(&signal.payload);
    let peer_addr: SocketAddr = match peer_addr_str.parse() {
        Ok(a) => a,
        Err(e) => {
            error!("P2P '{}': invalid peer addr '{}': {}", my_name, peer_addr_str, e);
            return;
        }
    };

    info!(
        "P2P responder '{}': received Offer from '{}' at {}",
        my_name, peer_name, peer_addr
    );

    // Create UDX runtime and bind socket
    let runtime = match UdxRuntime::new() {
        Ok(r) => r,
        Err(e) => {
            error!("P2P '{}': UDX runtime: {}", my_name, e);
            return;
        }
    };
    let socket = match runtime.create_socket().await {
        Ok(s) => s,
        Err(e) => {
            error!("P2P '{}': UDX socket: {}", my_name, e);
            return;
        }
    };
    if let Err(e) = socket.bind("0.0.0.0:0".parse().unwrap()).await {
        error!("P2P '{}': UDX bind: {}", my_name, e);
        return;
    }
    let local_addr = match socket.local_addr().await {
        Ok(a) => a,
        Err(e) => {
            error!("P2P '{}': local_addr: {}", my_name, e);
            return;
        }
    };

    info!("P2P responder '{}': UDX bound at {}", my_name, local_addr);

    // Discover public address via STUN
    let public_addr = if let Some(ref stun) = stun_server {
        stun_query(local_addr, stun).await
    } else {
        local_addr
    };

    // Respond with Answer, carrying our public UDP address
    let payload = public_addr.to_string().into_bytes();
    let reply = RfrpFrame::new_p2p_signal(
        P2pSignalType::Answer,
        &my_name,
        &peer_name,
        payload,
    );
    if tx_to_server.send(reply).await.is_err() {
        error!("P2P '{}': failed to send Answer", my_name);
        return;
    }
    info!("P2P responder '{}': Answer sent", my_name);

    // Accept the incoming UDX connection
    let stream = match runtime.create_stream(1).await {
        Ok(s) => s,
        Err(e) => {
            error!("P2P '{}': create stream: {}", my_name, e);
            return;
        }
    };
    if let Err(e) = stream.connect(&socket, 1, peer_addr).await {
        error!("P2P '{}': UDX connect: {}", my_name, e);
        return;
    }

    info!(
        "P2P responder '{}': UDX stream connected to {}",
        my_name, peer_addr
    );

    // Forward between UDX stream and internal TCP service
    forward_udx_to_tcp(stream, bind_port, cipher, &my_name, &peer_name, shutdown_rx).await
}

// ── Internal helpers ────────────────────────────────────────────────────────

/// Bidirectional forwarding between a UDX stream and a local TCP service.
async fn forward_udx_to_tcp(
    udx_stream: UdxStream,
    bind_port: u16,
    cipher: Arc<Cipher>,
    my_name: &str,
    peer_name: &str,
    shutdown_rx: ShutdownRx,
) {
    let udx = Arc::new(Mutex::new(udx_stream));
    let tcp_addr = format!("127.0.0.1:{}", bind_port);
    let tcp = match TcpStream::connect(&tcp_addr).await {
        Ok(s) => {
            if let Err(e) = s.set_nodelay(true) {
                warn!("P2P '{}': TCP_NODELAY: {}", my_name, e);
            }
            s
        }
        Err(e) => {
            error!(
                "P2P '{}': connect to internal service {}: {}",
                my_name, tcp_addr, e
            );
            return;
        }
    };

    info!(
        "P2P '{}': connected to internal service {} for peer '{}'",
        my_name, tcp_addr, peer_name
    );

    let (mut tcp_read, mut tcp_write) = tcp.into_split();

    // UDX → TCP
    let name1 = my_name.to_string();
    let mut shutdown1 = shutdown_rx.clone();
    let udx1 = Arc::clone(&udx);
    let cipher1 = Arc::clone(&cipher);
    let t1 = task::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown1.changed() => break,
                result = async {
                    let mut stream = udx1.lock().await;
                    stream.read().await
                } => {
                    match result {
                        Ok(Some(encrypted)) => {
                            let data = match cipher1.decrypt(&encrypted) {
                                Ok(d) => d,
                                Err(e) => {
                                    error!("P2P '{}': decrypt UDX: {}", name1, e);
                                    break;
                                }
                            };
                            if let Err(e) = tcp_write.write_all(&data).await {
                                error!("P2P '{}': write TCP: {}", name1, e);
                                break;
                            }
                        }
                        Ok(None) => {
                            info!("P2P '{}': UDX stream closed by peer", name1);
                            break;
                        }
                        Err(e) => {
                            error!("P2P '{}': read UDX: {}", name1, e);
                            break;
                        }
                    }
                }
            }
        }
        debug!("P2P '{}': UDX→TCP task ended", name1);
    });

    // TCP → UDX
    let name2 = my_name.to_string();
    let udx2 = Arc::clone(&udx);
    let cipher2 = Arc::clone(&cipher);
    let mut shutdown2 = shutdown_rx;
    let t2 = task::spawn(async move {
        let mut buf = [0u8; 32768];
        loop {
            tokio::select! {
                _ = shutdown2.changed() => break,
                result = tcp_read.read(&mut buf) => {
                    match result {
                        Ok(0) => {
                            info!("P2P '{}': TCP closed by internal service", name2);
                            break;
                        }
                        Ok(n) => {
                            let encrypted = cipher2.encrypt(&buf[..n]);
                            if let Err(e) = udx2.lock().await.write(&encrypted).await {
                                error!("P2P '{}': write UDX: {}", name2, e);
                                break;
                            }
                        }
                        Err(e) => {
                            error!("P2P '{}': read TCP: {}", name2, e);
                            break;
                        }
                    }
                }
            }
        }
        debug!("P2P '{}': TCP→UDX task ended", name2);
    });

    t1.await.ok();
    t2.await.ok();
    info!("P2P '{}': forward tasks ended for peer '{}'", my_name, peer_name);
}
