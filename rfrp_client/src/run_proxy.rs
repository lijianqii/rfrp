use bytes::Bytes;
use futures::SinkExt;
use log::{debug, error, info, warn};
use rfrp_config::config_info::base_info_ops::BaseInfoGetter;
use rfrp_config::config_info::base_types::{ClientInfo, ConfigInfo, P2pSignalType};
use rfrp_proto::crypto::{self, Cipher};
use rfrp_proto::frame_types::RfrpFrame;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tokio::task::{self, JoinHandle};
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

mod p2p_proxy;
use p2p_proxy::{handle_incoming_p2p_offer, query_and_connect, deliver_answer};
use p2p_proxy::{AnswerWaiters, PeerQueryWaiters};

type InternalConnMap = Arc<Mutex<HashMap<u64, mpsc::Sender<Vec<u8>>>>>;

pub async fn run_proxy(remote: TcpStream, config: ConfigInfo) {
    if let Err(e) = remote.set_nodelay(true) {
        warn!("Failed to set TCP_NODELAY on server socket: {}", e);
    }

    let key = crypto::derive_key(config.get_server().get_auth_token());
    let cipher = Arc::new(Cipher::new(&key));

    let (reader, writer) = remote.into_split();
    let mut reader = FramedRead::new(reader, LengthDelimitedCodec::new());
    let mut writer = FramedWrite::new(writer, LengthDelimitedCodec::new());

    let (tx_to_server, mut rx_to_server) = mpsc::channel::<RfrpFrame>(256);

    let write_cipher = Arc::clone(&cipher);
    let write_task = task::spawn(async move {
        while let Some(frame) = rx_to_server.recv().await {
            let bytes = RfrpFrame::encode_encrypted(&frame, &write_cipher);
            if let Err(e) = writer.send(Bytes::from(bytes)).await {
                error!("Failed to send frame to server: {}", e);
                break;
            }
        }
        info!("Write task ended");
    });

    // Shutdown signal: when dropped (or set to true), all P2P tasks stop.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // ── Phase 1: Register all proxies ────────────────────────────────────
    let mut p2p_proxies: Vec<ClientInfo> = Vec::new();

    for client_info in config.get_client_proxy() {
        let is_p2p = client_info.is_p2p();
        debug!("Registering {} proxy: {}", if is_p2p { "P2P" } else { "TCP" }, client_info.get_name());

        let reg_frame = RfrpFrame::Register(client_info.clone());
        if tx_to_server.send(reg_frame).await.is_err() {
            error!("Failed to send register frame");
            return;
        }

        match reader.next().await {
            Some(Ok(resp_bytes)) => match RfrpFrame::decode_encrypted(&resp_bytes, &cipher) {
                Ok(RfrpFrame::RegisterAck(resp)) => {
                    if resp.success {
                        info!("Registered proxy '{}' on bind_port {}", resp.client.get_name(), resp.client.get_bind_port());
                        if is_p2p { p2p_proxies.push(resp.client.clone()); }
                    } else {
                        error!("Server rejected registration for '{}'", client_info.get_name());
                    }
                }
                Ok(other) => error!("Unexpected frame during registration: {:?}", other),
                Err(e) => error!("Decode error during registration: {}", e),
            },
            Some(Err(e)) => { error!("Read error during registration: {}", e); return; }
            None => { error!("Server closed during registration"); return; }
        }
    }

    // ── Phase 1b: P2P dispatch ───────────────────────────────────────────
    let peer_query_waiters: PeerQueryWaiters = Arc::new(Mutex::new(HashMap::new()));
    let answer_waiters: AnswerWaiters = Arc::new(Mutex::new(HashMap::new()));
    let mut p2p_handles: Vec<JoinHandle<()>> = Vec::new();

    for p2p_client in &p2p_proxies {
        let my_name = p2p_client.get_name().to_string();
        let stun_server = p2p_client.get_p2p_stun_server().map(|s| s.to_string());
        let tx = tx_to_server.clone();
        let c = Arc::clone(&cipher);
        let qw = peer_query_waiters.clone();
        let aw = answer_waiters.clone();
        let sr = shutdown_rx.clone();

        match p2p_client.get_p2p_peer_name() {
            Some(peer_name) => {
                let peer = peer_name.to_string();
                let bind_port = p2p_client.get_bind_port();
                info!("P2P '{}': active mode → peer '{}', listening on :{}", my_name, peer, bind_port);
                let h = task::spawn(async move {
                    query_and_connect(&my_name, &peer, stun_server, bind_port, tx, c, qw, aw, sr).await;
                });
                p2p_handles.push(h);
            }
            None => {
                info!("P2P '{}': passive mode, waiting for Offers", my_name);
            }
        }
    }

    info!("All proxies registered, entering data forwarding loop");

    let internal_conns: InternalConnMap = Arc::new(Mutex::new(HashMap::new()));

    // ── Phase 2: Main loop ───────────────────────────────────────────────
    loop {
        let bytes = match reader.next().await {
            Some(Ok(b)) => b,
            Some(Err(e)) => { error!("Read error: {}", e); break; }
            None => { info!("Server closed connection"); break; }
        };

        let frame = match RfrpFrame::decode_encrypted(&bytes, &cipher) {
            Ok(f) => f,
            Err(e) => { error!("Decode: {}", e); continue; }
        };

        match frame {
            RfrpFrame::Data(data_info) => {
                let conn_id = data_info.conn_id;
                let data = data_info.data;
                let tx = tx_to_server.clone();
                let conns = internal_conns.clone();
                let sender = get_or_create_internal_conn(&conns, conn_id, &data_info.client, tx).await;
                match sender {
                    Some(s) => { if s.send(data).await.is_err() { conns.lock().await.remove(&conn_id); } }
                    None => error!("Cannot reach internal service {} for conn {}", data_info.client.get_addr(), conn_id),
                }
            }
            RfrpFrame::Control(ci) => debug!("Control: {:?}", ci),
            RfrpFrame::Register(c) => warn!("Unexpected Register: {}", c.get_name()),
            RfrpFrame::RegisterAck(r) => warn!("Unexpected RegisterAck: {}", r.client.get_name()),

            RfrpFrame::P2pSignal(sig) => {
                match sig.signal_type {
                    P2pSignalType::PeerResponse => {
                        let found: bool = serde_json::from_slice(&sig.payload).ok()
                            .and_then(|v: serde_json::Value| v.get("found")?.as_bool()).unwrap_or(false);
                        let drained: Vec<_> = peer_query_waiters.lock().await.drain().collect();
                        for (_name, tx) in drained { let _ = tx.send(found); }
                    }
                    P2pSignalType::Offer => {
                        let tx = tx_to_server.clone();
                        let c = Arc::clone(&cipher);
                        let from = sig.from_client.clone();
                        let to = sig.to_client.clone();
                        let payload = sig.payload.clone();
                        let proxy_ip = p2p_proxies.iter()
                            .find(|p| p.get_name() == to)
                            .map(|p| p.get_ip().to_string())
                            .unwrap_or_else(|| "127.0.0.1".to_string());
                        let proxy_port = p2p_proxies.iter()
                            .find(|p| p.get_name() == to)
                            .map(|p| p.get_port())
                            .unwrap_or(0);
                        let sr = shutdown_rx.clone();
                        task::spawn(async move {
                            if let Err(e) = handle_incoming_p2p_offer(
                                &from, &to, &payload, &proxy_ip, proxy_port, tx, c, sr,
                            ).await {
                                error!("handle_incoming_p2p_offer: {}", e);
                            }
                        });
                    }
                    P2pSignalType::Answer => {
                        deliver_answer(&sig.from_client, &sig.to_client, &sig.payload, &answer_waiters).await;
                    }
                    P2pSignalType::Candidate => debug!("Candidate from {}", sig.from_client),
                    P2pSignalType::Ping | P2pSignalType::Pong => debug!("{:?} from {}", sig.signal_type, sig.from_client),
                    P2pSignalType::PeerQuery => warn!("Unexpected PeerQuery on client"),
                }
            }
            RfrpFrame::P2pData(_) => debug!("P2pData received on TCP tunnel (unexpected)"),
        }
    }

    // ── Cleanup ──────────────────────────────────────────────────────────
    info!("Shutting down P2P tasks...");
    let _ = shutdown_tx.send(true);
    for h in p2p_handles { h.abort(); }
    write_task.abort();
    info!("Client proxy session ended");
}

async fn get_or_create_internal_conn(
    conns: &InternalConnMap,
    conn_id: u64,
    client_info: &ClientInfo,
    tx_to_server: mpsc::Sender<RfrpFrame>,
) -> Option<mpsc::Sender<Vec<u8>>> {
    {
        let map = conns.lock().await;
        if let Some(s) = map.get(&conn_id) { return Some(s.clone()); }
    }

    let addr = client_info.get_addr();
    info!("Opening TCP to internal service {} for conn {}", addr, conn_id);
    let stream = match TcpStream::connect(&addr).await {
        Ok(s) => { let _ = s.set_nodelay(true); s }
        Err(e) => { error!("TCP connect to {}: {}", addr, e); return None; }
    };

    let (mut rh, mut wh) = stream.into_split();
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(128);
    conns.lock().await.insert(conn_id, tx.clone());

    let ci_name = client_info.get_name().to_string();
    let cid = conn_id;
    task::spawn(async move {
        while let Some(data) = rx.recv().await {
            if wh.write_all(&data).await.is_err() { break; }
        }
        debug!("Write task '{}' conn {} ended", ci_name, cid);
    });

    let ci = client_info.clone();
    let cid = conn_id;
    let conns_c = Arc::clone(conns);
    task::spawn(async move {
        let mut buf = [0u8; 32768];
        loop {
            match rh.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let frame = RfrpFrame::new_data_frame(&buf[..n], &ci, cid);
                    if tx_to_server.send(frame).await.is_err() { break; }
                }
                Err(_) => break,
            }
        }
        conns_c.lock().await.remove(&cid);
        info!("Cleaned up internal conn for '{}' conn {}", ci.get_name(), cid);
    });

    Some(tx)
}
