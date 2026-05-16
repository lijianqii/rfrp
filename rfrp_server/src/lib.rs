mod run_proxy;

use log::{error, info, warn};
use rfrp_config::config_info::base_info_ops::BaseInfoGetter;
use rfrp_config::config_info::base_types::ConfigInfo;
use rfrp_proto::P2pPeerTable;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use run_proxy::run_proxy;

pub async fn rfrp_server(config: ConfigInfo) {
    info!(
        "Running in server mode, listening on {}:{}",
        config.get_server().get_ip(),
        config.get_server().get_port()
    );

    // Shared P2P peer table — all client connections share this.
    // Maps client name → channel to send frames to that client.
    let p2p_peers: P2pPeerTable = Arc::new(Mutex::new(HashMap::new()));

    let listener = tokio::net::TcpListener::bind(&config.get_server().get_addr())
        .await
        .unwrap();
    loop {
        let (socket, peer) = match listener.accept().await {
            Ok((socket, peer)) => (socket, peer),
            Err(e) => {
                error!("Failed to accept connection: {}", e);
                continue;
            }
        };
        info!("Accepted connection from {}", peer);

        // Disable Nagle's algorithm for low-latency forwarding
        if let Err(e) = socket.set_nodelay(true) {
            warn!("Failed to set TCP_NODELAY on accepted socket: {}", e);
        }

        let auth_token = config.get_server().get_auth_token().to_string();
        let peers = p2p_peers.clone();

        tokio::task::spawn(run_proxy(socket, auth_token, peers));
    }
}
