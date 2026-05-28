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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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
/// Maximum time to wait for UDX stream creation and connection.
const UDX_CONNECT_TIMEOUT_SECS: u64 = 20;
/// Maximum time to wait for TCP connection to internal service.
const TCP_CONNECT_TIMEOUT_SECS: u64 = 10;
/// Number of STUN query retries before falling back to local address.
const STUN_MAX_RETRIES: u32 = 3;

// ── STUN ────────────────────────────────────────────────────────────────────

/// Query a STUN server for our public UDP address with retries.
///
/// Resolves the STUN server hostname, sends a Binding Request, and parses
/// the XOR-MAPPED-ADDRESS or MAPPED-ADDRESS from the response. Retries up
/// to `STUN_MAX_RETRIES` times before falling back to `local_addr`.
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
                    Ok(mut addrs) => match addrs.next() {
                        Some(addr) => addr,
                        None => {
                            warn!("P2P: STUN DNS resolved no addresses for '{}'", host);
                            return local_addr;
                        }
                    },
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

    for attempt in 1..=STUN_MAX_RETRIES {
        match stun_bind_request(stun_addr).await {
            Some(addr) => {
                info!(
                    "P2P: STUN mapped address: {} (local: {}, attempt {}/{})",
                    addr, local_addr, attempt, STUN_MAX_RETRIES
                );
                return addr;
            }
            None if attempt < STUN_MAX_RETRIES => {
                warn!(
                    "P2P: STUN attempt {}/{} failed, retrying...",
                    attempt, STUN_MAX_RETRIES
                );
                time::sleep(Duration::from_millis(500)).await;
            }
            None => {
                warn!("P2P: STUN all {} attempts failed", STUN_MAX_RETRIES);
            }
        }
    }
    local_addr
}

/// Send a single STUN Binding Request and parse the mapped address from the response.
///
/// Validates that the response comes from the expected STUN server address and
/// has a valid magic cookie. Supports both XOR-MAPPED-ADDRESS (RFC 5389) and
/// legacy MAPPED-ADDRESS (RFC 3489) for IPv4 and IPv6.
async fn stun_bind_request(stun_addr: SocketAddr) -> Option<SocketAddr> {
    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;

    // STUN Binding Request: type=0x0001, length=0, magic=0x2112A442, tid=zeros
    let request: [u8; 20] = [
        0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    sock.send_to(&request, stun_addr).await.ok()?;

    // Larger buffer to accommodate IPv6 responses
    let mut buf = [0u8; 128];
    let (n, from) = match time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf)).await {
        Ok(Ok((n, from))) => (n, from),
        _ => return None,
    };

    // Validate response comes from the STUN server we sent to
    if from != stun_addr {
        warn!(
            "P2P: STUN response from unexpected {} (expected {}), ignoring",
            from, stun_addr
        );
        return None;
    }

    if n < 20 {
        return None;
    }

    // Verify magic cookie (RFC 5389 §6)
    if buf[4..8] != [0x21, 0x12, 0xA4, 0x42] {
        warn!("P2P: STUN response has invalid magic cookie");
        return None;
    }

    // Parse attributes looking for XOR-MAPPED-ADDRESS or MAPPED-ADDRESS
    let mut pos = 20;
    while pos + 4 <= n {
        let attr_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let attr_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;
        if pos + attr_len > n {
            break;
        }

        let result = match attr_type {
            0x0020 => parse_xor_mapped_address(&buf[pos..pos + attr_len]),
            0x0001 => parse_mapped_address(&buf[pos..pos + attr_len]),
            _ => None,
        };
        if result.is_some() {
            return result;
        }

        pos += attr_len;
        pos = (pos + 3) & !3; // 4-byte alignment per RFC
    }

    None
}

/// Parse XOR-MAPPED-ADDRESS attribute (RFC 5389 §15.2).
///
/// Supports both IPv4 (family 0x01, 8 bytes) and IPv6 (family 0x02, 20 bytes).
fn parse_xor_mapped_address(data: &[u8]) -> Option<SocketAddr> {
    if data.len() < 8 {
        return None;
    }
    let family = data[1];
    let xport = u16::from_be_bytes([data[2], data[3]]);
    let port = xport ^ 0x2112;

    match family {
        0x01 => {
            let xip = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            let ip = Ipv4Addr::from(xip ^ 0x2112A442);
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x02 if data.len() >= 20 => {
            let mut xip = [0u8; 16];
            xip.copy_from_slice(&data[4..20]);
            // XOR with magic cookie (4 bytes) + transaction ID (12 bytes)
            // Since our transaction ID is all zeros, only the cookie bytes are flipped.
            xip[0] ^= 0x21;
            xip[1] ^= 0x12;
            xip[2] ^= 0xA4;
            xip[3] ^= 0x42;
            let ip = Ipv6Addr::from(xip);
            Some(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => None,
    }
}

/// Parse MAPPED-ADDRESS attribute (RFC 3489, legacy).
///
/// Supports both IPv4 (family 0x01, 8 bytes) and IPv6 (family 0x02, 20 bytes).
fn parse_mapped_address(data: &[u8]) -> Option<SocketAddr> {
    if data.len() < 8 {
        return None;
    }
    let family = data[1];
    let port = u16::from_be_bytes([data[2], data[3]]);

    match family {
        0x01 => {
            let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x02 if data.len() >= 20 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[4..20]);
            let ip = Ipv6Addr::from(octets);
            Some(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => None,
    }
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
    info!(
        "P2P '{}': starting peer query loop for '{}'",
        my_name, peer_name
    );

    loop {
        let (tx, mut rx) = oneshot::channel();
        {
            query_waiters.lock().await.insert(peer_name.clone(), tx);
        }

        let query = RfrpFrame::new_p2p_signal(P2pSignalType::PeerQuery, &my_name, &peer_name, vec![]);
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
    let offer = RfrpFrame::new_p2p_signal(P2pSignalType::Offer, my_name, peer_name, payload);
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

    // Connect via UDX (with timeout to prevent hanging on NAT traversal failure)
    let stream = time::timeout(
        Duration::from_secs(UDX_CONNECT_TIMEOUT_SECS),
        runtime.create_stream(1),
    )
    .await
    .map_err(|_| "create stream timeout".to_string())?
    .map_err(|e| format!("create stream: {}", e))?;
    time::timeout(
        Duration::from_secs(UDX_CONNECT_TIMEOUT_SECS),
        stream.connect(&socket, 1, peer_addr),
    )
    .await
    .map_err(|_| "UDX connect timeout".to_string())?
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
            error!(
                "P2P '{}': invalid peer addr '{}': {}",
                my_name, peer_addr_str, e
            );
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
    let reply = RfrpFrame::new_p2p_signal(P2pSignalType::Answer, &my_name, &peer_name, payload);
    if tx_to_server.send(reply).await.is_err() {
        error!("P2P '{}': failed to send Answer", my_name);
        return;
    }
    info!("P2P responder '{}': Answer sent", my_name);

    // Accept the incoming UDX connection (with timeout to prevent hanging)
    let stream = match time::timeout(
        Duration::from_secs(UDX_CONNECT_TIMEOUT_SECS),
        runtime.create_stream(1),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            error!("P2P '{}': create stream: {}", my_name, e);
            return;
        }
        Err(_) => {
            error!("P2P '{}': create stream timed out", my_name);
            return;
        }
    };
    match time::timeout(
        Duration::from_secs(UDX_CONNECT_TIMEOUT_SECS),
        stream.connect(&socket, 1, peer_addr),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            error!("P2P '{}': UDX connect: {}", my_name, e);
            return;
        }
        Err(_) => {
            error!("P2P '{}': UDX connect timed out", my_name);
            return;
        }
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
///
/// Instead of wrapping the UDX stream in `Arc<Mutex<>>` (which serializes
/// reads and writes), the stream is owned by a single task that multiplexes
/// both directions via `tokio::select!`. The TCP→UDX path sends encrypted
/// data through an mpsc channel, eliminating lock contention entirely.
async fn forward_udx_to_tcp(
    mut udx_stream: UdxStream,
    bind_port: u16,
    cipher: Arc<Cipher>,
    my_name: &str,
    peer_name: &str,
    shutdown_rx: ShutdownRx,
) {
    let tcp_addr = format!("127.0.0.1:{}", bind_port);
    let tcp = match time::timeout(
        Duration::from_secs(TCP_CONNECT_TIMEOUT_SECS),
        TcpStream::connect(&tcp_addr),
    )
    .await
    {
        Ok(Ok(s)) => {
            if let Err(e) = s.set_nodelay(true) {
                warn!("P2P '{}': TCP_NODELAY: {}", my_name, e);
            }
            s
        }
        Ok(Err(e)) => {
            error!(
                "P2P '{}': connect to internal service {}: {}",
                my_name, tcp_addr, e
            );
            return;
        }
        Err(_) => {
            error!(
                "P2P '{}': connect to internal service {} timed out",
                my_name, tcp_addr
            );
            return;
        }
    };

    info!(
        "P2P '{}': connected to internal service {} for peer '{}'",
        my_name, tcp_addr, peer_name
    );

    let (mut tcp_read, mut tcp_write) = tcp.into_split();

    // Channel for TCP→UDX direction — eliminates Arc<Mutex<UdxStream>> contention.
    // The UDX task owns the stream exclusively and receives write requests here.
    let (udx_write_tx, mut udx_write_rx) = mpsc::channel::<Vec<u8>>(256);

    let (mut shutdown_udx, mut shutdown_tcp) = (shutdown_rx.clone(), shutdown_rx);
    let name1 = my_name.to_string();
    let cipher1 = Arc::clone(&cipher);

    // Single UDX task: multiplexes reads (UDX→TCP) and writes (channel→UDX).
    // By owning the stream exclusively, we avoid Arc<Mutex<>> contention and
    // allow true full-duplex forwarding.
    let t1 = task::spawn(async move {
        loop {
            tokio::select! {
                biased;

                _ = shutdown_udx.changed() => break,

                // UDX → TCP: read from UDX, decrypt, write to TCP
                result = udx_stream.read() => {
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

                // TCP → UDX: receive encrypted data from channel, write to UDX
                Some(data) = udx_write_rx.recv() => {
                    if let Err(e) = udx_stream.write(&data).await {
                        error!("P2P '{}': write UDX: {}", name1, e);
                        break;
                    }
                }
            }
        }
        debug!("P2P '{}': UDX task ended", name1);
    });

    // TCP read task: reads from internal service, encrypts, sends to UDX task via channel.
    let name2 = my_name.to_string();
    let cipher2 = Arc::clone(&cipher);
    let t2 = task::spawn(async move {
        let mut buf = [0u8; 32768];
        loop {
            tokio::select! {
                biased;

                _ = shutdown_tcp.changed() => break,

                result = tcp_read.read(&mut buf) => {
                    match result {
                        Ok(0) => {
                            info!("P2P '{}': TCP closed by internal service", name2);
                            break;
                        }
                        Ok(n) => {
                            let encrypted = cipher2.encrypt(&buf[..n]);
                            if udx_write_tx.send(encrypted).await.is_err() {
                                // UDX task has exited, no point continuing
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
        debug!("P2P '{}': TCP read task ended", name2);
    });

    // Wait for both tasks. If one panics or exits early, the other will
    // eventually notice (channel closed / UDX stream closed) and exit too.
    t1.await.ok();
    t2.await.ok();
    info!(
        "P2P '{}': forward tasks ended for peer '{}'" ,
        my_name, peer_name
    );
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "tests/p2p_tests.rs"]
mod tests;
