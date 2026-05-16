//! P2P proxy module: UDP hole punching, STUN-based NAT traversal,
//! and bidirectional TCP↔UDP data forwarding with per-conn_id connection tracking.

use log::{debug, error, info, warn};
use rfrp_config::config_info::base_types::P2pSignalType;
use rfrp_proto::crypto::Cipher;
use rfrp_proto::frame_types::RfrpFrame;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::task;
use tokio::time::{self, Duration};

// ── Constants ───────────────────────────────────────────────────────────────

const UDP_BUF_SIZE: usize = 65535;
#[allow(dead_code)]
const KEEP_ALIVE_INTERVAL_SECS: u64 = 15;
const HOLE_PUNCH_PACKETS: usize = 5;
const HOLE_PUNCH_DELAY_MS: u64 = 100;
const PEER_QUERY_RETRY_SECS: u64 = 5;
const ANSWER_TIMEOUT_SECS: u64 = 15;

// ── Types ───────────────────────────────────────────────────────────────────

pub type PeerQueryWaiters = Arc<Mutex<HashMap<String, tokio::sync::oneshot::Sender<bool>>>>;
pub type AnswerWaiters = Arc<Mutex<HashMap<String, tokio::sync::oneshot::Sender<SocketAddr>>>>;

struct ConnPipe { tcp_tx: mpsc::Sender<Vec<u8>> }
type ActiveConnTable = Arc<Mutex<HashMap<u64, ConnPipe>>>;
type PassiveConnTable = Arc<Mutex<HashMap<u64, ConnPipe>>>;
type ShutdownRx = watch::Receiver<bool>;

// ── Public API ──────────────────────────────────────────────────────────────

pub async fn query_and_connect(
    my_name: &str, peer_name: &str,
    stun_server: Option<String>, bind_port: u16,
    tx_to_server: mpsc::Sender<RfrpFrame>, cipher: Arc<Cipher>,
    query_waiters: PeerQueryWaiters, answer_waiters: AnswerWaiters,
    mut shutdown_rx: ShutdownRx,
) {
    let my_name = my_name.to_string();
    let peer_name = peer_name.to_string();
    info!("P2P '{}': starting peer query loop for '{}'", my_name, peer_name);

    loop {
        let (tx, mut rx) = tokio::sync::oneshot::channel();
        { query_waiters.lock().await.insert(peer_name.clone(), tx); }

        let query = RfrpFrame::new_p2p_signal(P2pSignalType::PeerQuery, &my_name, &peer_name, vec![]);
        if tx_to_server.send(query).await.is_err() {
            error!("P2P '{}': channel to server closed", my_name);
            return;
        }

        tokio::select! {
            _ = shutdown_rx.changed() => { info!("P2P '{}': shutdown", my_name); return; }
            result = time::timeout(Duration::from_secs(PEER_QUERY_RETRY_SECS + 2), &mut rx) => {
                match result {
                    Ok(Ok(true)) => {
                        info!("P2P '{}': peer '{}' online, initiating", my_name, peer_name);
                        match initiate_p2p_connection(
                            &my_name, &peer_name, stun_server.clone(), bind_port,
                            tx_to_server.clone(), cipher.clone(), answer_waiters.clone(),
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
            _ = shutdown_rx.changed() => { info!("P2P '{}': shutdown", my_name); return; }
            _ = time::sleep(Duration::from_secs(PEER_QUERY_RETRY_SECS)) => {}
        }
    }
}

pub async fn initiate_p2p_connection(
    my_name: &str, peer_name: &str,
    stun_server: Option<String>, bind_port: u16,
    tx_to_server: mpsc::Sender<RfrpFrame>, cipher: Arc<Cipher>,
    answer_waiters: AnswerWaiters, shutdown_rx: ShutdownRx,
) -> Result<(), String> {
    let udp = Arc::new(UdpSocket::bind("0.0.0.0:0").await.map_err(|e| format!("UDP bind: {}", e))?);
    let local_udp = udp.local_addr().map_err(|e| format!("local_addr: {}", e))?;
    info!("P2P initiator '{}': UDP bound at {}", my_name, local_udp);

    let public_addr = match stun_server {
        Some(ref stun) => match query_stun(&udp, stun).await {
            Ok(a) => { info!("P2P initiator '{}': STUN → {}", my_name, a); Some(a) }
            Err(e) => { warn!("P2P initiator '{}': STUN failed: {}", my_name, e); None }
        },
        None => None,
    };

    let offer = serde_json::json!({"local_addr":local_udp.to_string(),"public_addr":public_addr.map(|a|a.to_string())});
    tx_to_server.send(RfrpFrame::new_p2p_signal(P2pSignalType::Offer, my_name, peer_name, serde_json::to_vec(&offer).unwrap()))
        .await.map_err(|e| format!("send Offer: {}", e))?;
    info!("P2P initiator '{}': Offer sent", my_name);

    let answer_key = format!("{}:{}", my_name, peer_name);
    let (ans_tx, mut ans_rx) = tokio::sync::oneshot::channel();
    { answer_waiters.lock().await.insert(answer_key, ans_tx); }
    let peer_udp: SocketAddr = time::timeout(Duration::from_secs(ANSWER_TIMEOUT_SECS), &mut ans_rx)
        .await.map_err(|_| "Answer timeout".to_string())?
        .map_err(|_| "Answer channel closed".to_string())?;
    info!("P2P initiator '{}': peer UDP = {}", my_name, peer_udp);

    for i in 0..HOLE_PUNCH_PACKETS {
        let punch = cipher.encrypt(format!("HOLE_PUNCH_{}", i).as_bytes());
        let _ = udp.send_to(&punch, peer_udp).await;
        time::sleep(Duration::from_millis(HOLE_PUNCH_DELAY_MS)).await;
    }

    let conn_table: ActiveConnTable = Arc::new(Mutex::new(HashMap::new()));

    // UDP recv task
    let udp_recv = udp.clone();
    let ct_recv = conn_table.clone();
    let mn_recv = my_name.to_string();
    let ciph_recv = cipher.clone();
    let mut sr_recv = shutdown_rx.clone();
    task::spawn(async move {
        let mut buf = [0u8; UDP_BUF_SIZE];
        loop {
            tokio::select! {
                _ = sr_recv.changed() => break,
                result = udp_recv.recv_from(&mut buf) => {
                    match result {
                        Ok((n, _)) => {
                            let plain = match ciph_recv.decrypt(&buf[..n]) {
                                Ok(p) => p, Err(_) => continue,
                            };
                            if plain.len() < 8 { continue; }
                            let cid = u64::from_be_bytes(plain[..8].try_into().unwrap());
                            let table = ct_recv.lock().await;
                            if let Some(pipe) = table.get(&cid) {
                                let _ = pipe.tcp_tx.send(plain[8..].to_vec()).await;
                            }
                        }
                        Err(e) => { error!("P2P initiator '{}': UDP: {}", mn_recv, e); break; }
                    }
                }
            }
        }
    });

    // TCP listener task
    let listener = TcpListener::bind(format!("0.0.0.0:{}", bind_port)).await
        .map_err(|e| format!("TCP bind :{}: {}", bind_port, e))?;
    info!("P2P initiator '{}': TCP listener on :{}", my_name, bind_port);

    let mut next_cid: u64 = 0;
    let mn = my_name.to_string();
    let mut sr_listen = shutdown_rx.clone();
    task::spawn(async move {
        loop {
            let (tcp, src) = tokio::select! {
                _ = sr_listen.changed() => break,
                result = listener.accept() => match result {
                    Ok(c) => c,
                    Err(e) => { error!("P2P '{}' accept: {}", mn, e); break; }
                },
            };
            let cid = next_cid; next_cid = next_cid.wrapping_add(1);
            info!("P2P '{}': accepted conn {} from {}", mn, cid, src);
            let _ = tcp.set_nodelay(true);

            let (mut tcp_read, mut tcp_write) = tcp.into_split();
            let (tcp_tx, mut tcp_rx) = mpsc::channel::<Vec<u8>>(128);
            conn_table.lock().await.insert(cid, ConnPipe { tcp_tx });

            let u = udp.clone();
            let mn2 = mn.clone();
            let ciph_out = cipher.clone();
            let mut sr_tcp = shutdown_rx.clone();
            task::spawn(async move {
                let mut buf = [0u8; UDP_BUF_SIZE - 8];
                loop {
                    tokio::select! {
                        _ = sr_tcp.changed() => break,
                        result = tcp_read.read(&mut buf) => {
                            match result {
                                Ok(0) => { info!("P2P '{}' conn {}: TCP closed", mn2, cid); break; }
                                Ok(n) => {
                                    let mut pkt = cid.to_be_bytes().to_vec();
                                    pkt.extend_from_slice(&buf[..n]);
                                    if u.send_to(&ciph_out.encrypt(&pkt), peer_udp).await.is_err() { break; }
                                }
                                Err(e) => { error!("P2P '{}' conn {}: TCP read: {}", mn2, cid, e); break; }
                            }
                        }
                    }
                }
            });

            let mn3 = mn.clone();
            let ct = conn_table.clone();
            task::spawn(async move {
                while let Some(data) = tcp_rx.recv().await {
                    if tcp_write.write_all(&data).await.is_err() { break; }
                }
                ct.lock().await.remove(&cid);
                info!("P2P '{}' conn {}: cleaned up", mn3, cid);
            });
        }
        info!("P2P '{}': TCP listener stopped", mn);
    });

    Ok(())
}

pub async fn handle_incoming_p2p_offer(
    from_client: &str, to_client: &str, payload: &[u8],
    proxy_ip: &str, proxy_port: u16,
    tx_to_server: mpsc::Sender<RfrpFrame>, cipher: Arc<Cipher>,
    mut shutdown_rx: ShutdownRx,
) -> Result<(), String> {
    let offer: serde_json::Value = serde_json::from_slice(payload).map_err(|e| format!("bad Offer: {}", e))?;
    let peer_local: SocketAddr = offer["local_addr"].as_str().ok_or("missing local_addr")?
        .parse().map_err(|e| format!("local_addr: {}", e))?;
    let peer_public: Option<SocketAddr> = offer["public_addr"].as_str().and_then(|s| s.parse().ok());
    info!("P2P responder '{}': Offer from '{}', peer={}", to_client, from_client, peer_local);

    let udp = Arc::new(UdpSocket::bind("0.0.0.0:0").await.map_err(|e| format!("UDP bind: {}", e))?);
    let local_udp = udp.local_addr().map_err(|e| format!("local_addr: {}", e))?;
    info!("P2P responder '{}': UDP bound at {}", to_client, local_udp);

    let ans = serde_json::json!({"local_addr":local_udp.to_string()});
    tx_to_server.send(RfrpFrame::new_p2p_signal(P2pSignalType::Answer, to_client, from_client, serde_json::to_vec(&ans).unwrap()))
        .await.map_err(|e| format!("send Answer: {}", e))?;

    let targets: Vec<SocketAddr> = peer_public.into_iter().chain(Some(peer_local)).collect();
    for &addr in &targets {
        let u = udp.clone(); let ciph = cipher.clone();
        task::spawn(async move {
            for i in 0..HOLE_PUNCH_PACKETS {
                let _ = u.send_to(&ciph.encrypt(format!("HOLE_PUNCH_{}", i).as_bytes()), addr).await;
                time::sleep(Duration::from_millis(HOLE_PUNCH_DELAY_MS)).await;
            }
        });
    }

    let conn_table: PassiveConnTable = Arc::new(Mutex::new(HashMap::new()));
    let proxy_addr = format!("{}:{}", proxy_ip, proxy_port);
    let to = to_client.to_string();
    let my_udp = udp.clone();
    let ciph_dec = cipher.clone();
    task::spawn(async move {
        let mut buf = [0u8; UDP_BUF_SIZE];
        let mut known_peer: Option<SocketAddr> = None;
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                result = my_udp.recv_from(&mut buf) => {
                    match result {
                        Ok((n, src)) => {
                            if known_peer.is_none() { known_peer = Some(src); info!("P2P responder '{}': first pkt from {}", to, src); }
                            let plain = match ciph_dec.decrypt(&buf[..n]) {
                                Ok(p) => p, Err(_) => continue,
                            };
                            if plain.len() < 8 { continue; }
                            let conn_id = u64::from_be_bytes(plain[..8].try_into().unwrap());
                            let payload = plain[8..].to_vec();

                            let mut table = conn_table.lock().await;
                            if let Some(pipe) = table.get(&conn_id) {
                                let _ = pipe.tcp_tx.send(payload).await;
                            } else {
                                info!("P2P responder '{}': new conn {}, opening TCP to {}", to, conn_id, proxy_addr);
                                match TcpStream::connect(&proxy_addr).await {
                                    Ok(tcp) => {
                                        let _ = tcp.set_nodelay(true);
                                        let (mut tcp_read, mut tcp_write) = tcp.into_split();
                                        let (tcp_tx, mut tcp_rx) = mpsc::channel::<Vec<u8>>(128);
                                        table.insert(conn_id, ConnPipe { tcp_tx });
                                        if tcp_write.write_all(&payload).await.is_err() {
                                            table.remove(&conn_id); continue;
                                        }

                                        let u2 = my_udp.clone();
                                        let peer = known_peer.unwrap_or(src);
                                        let tn = to.clone();
                                        let cid = conn_id;
                                        let ct = conn_table.clone();
                                        let ciph_enc = cipher.clone();
                                        let mut sr_inner = shutdown_rx.clone();
                                        task::spawn(async move {
                                            let mut b = [0u8; UDP_BUF_SIZE - 8];
                                            loop {
                                                tokio::select! {
                                                    _ = sr_inner.changed() => break,
                                                    result = tcp_read.read(&mut b) => {
                                                        match result {
                                                            Ok(0) => { info!("P2P '{}' conn {}: TCP closed", tn, cid); break; }
                                                            Ok(n) => {
                                                                let mut pkt = cid.to_be_bytes().to_vec();
                                                                pkt.extend_from_slice(&b[..n]);
                                                                if u2.send_to(&ciph_enc.encrypt(&pkt), peer).await.is_err() { break; }
                                                            }
                                                            Err(e) => { error!("P2P '{}' conn {}: TCP read: {}", tn, cid, e); break; }
                                                        }
                                                    }
                                                }
                                            }
                                            ct.lock().await.remove(&cid);
                                        });

                                        let ct2 = conn_table.clone();
                                        let cid2 = conn_id;
                                        task::spawn(async move {
                                            while let Some(data) = tcp_rx.recv().await {
                                                if tcp_write.write_all(&data).await.is_err() { break; }
                                            }
                                            ct2.lock().await.remove(&cid2);
                                        });
                                    }
                                    Err(e) => error!("P2P responder '{}': TCP connect {}: {}", to, proxy_addr, e),
                                }
                            }
                        }
                        Err(e) => { error!("P2P responder '{}': UDP: {}", to, e); break; }
                    }
                }
            }
        }
        info!("P2P responder '{}': stopped", to);
    });

    Ok(())
}

pub async fn deliver_answer(from_client: &str, to_client: &str, payload: &[u8], answer_waiters: &AnswerWaiters) {
    let key = format!("{}:{}", to_client, from_client);
    let addr: Option<SocketAddr> = serde_json::from_slice::<serde_json::Value>(payload).ok()
        .and_then(|v| v.get("local_addr")?.as_str()?.parse().ok());
    if let Some(a) = addr {
        if let Some(tx) = answer_waiters.lock().await.remove(&key) { let _ = tx.send(a); }
    }
}

// ── STUN ────────────────────────────────────────────────────────────────────

async fn query_stun(socket: &UdpSocket, stun_server: &str) -> Result<SocketAddr, String> {
    let mut req = Vec::with_capacity(20);
    req.extend_from_slice(&[0x00, 0x01]);
    req.extend_from_slice(&[0x00, 0x00]);
    req.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
    for _ in 0..12 { req.push(rand::random::<u8>()); }

    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(stun_server)
        .await.map_err(|e| format!("STUN resolve '{}': {}", stun_server, e))?.collect();
    let mut last_err = String::new();
    let mut sent = false;
    for &addr in &addrs {
        match socket.send_to(&req, addr).await {
            Ok(_) => { sent = true; break; }
            Err(e) => { last_err = format!("{}: {}", addr, e); }
        }
    }
    if !sent { return Err(format!("STUN send: {}", last_err)); }

    let mut buf = [0u8; 256];
    let (n, _) = time::timeout(Duration::from_secs(3), socket.recv_from(&mut buf))
        .await.map_err(|_| "STUN timeout".to_string())?
        .map_err(|e| format!("STUN recv: {}", e))?;
    let resp = &buf[..n];

    if resp.len() < 20 || u16::from_be_bytes([resp[0], resp[1]]) != 0x0101 {
        return Err("bad STUN response".into());
    }
    let msg_len = u16::from_be_bytes([resp[2], resp[3]]) as usize;

    let mut off = 20;
    while off + 4 <= resp.len().min(20 + msg_len) {
        let at = u16::from_be_bytes([resp[off], resp[off+1]]);
        let al = u16::from_be_bytes([resp[off+2], resp[off+3]]) as usize;
        off += 4;
        if off + al > resp.len() { break; }
        let parse_ipv4 = |b: &[u8]| -> Option<SocketAddr> {
            if b.len() >= 8 && b[1] == 0x01 {
                Some(SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(b[4],b[5],b[6],b[7])),
                    u16::from_be_bytes([b[2],b[3]])))
            } else { None }
        };
        match at {
            0x0001 => { if let Some(a) = parse_ipv4(&resp[off..]) { return Ok(a); } }
            0x0020 => {
                if al >= 8 && resp[off+1] == 0x01 {
                    let mc = [0x21,0x12,0xA4,0x42];
                    let port = u16::from_be_bytes([resp[off+2],resp[off+3]]) ^ 0x2112;
                    let ip = std::net::Ipv4Addr::new(resp[off+4]^mc[0],resp[off+5]^mc[1],resp[off+6]^mc[2],resp[off+7]^mc[3]);
                    return Ok(SocketAddr::new(std::net::IpAddr::V4(ip), port));
                }
            }
            _ => {}
        }
        off += (al + 3) & !3;
    }
    Err("No address in STUN response".into())
}
