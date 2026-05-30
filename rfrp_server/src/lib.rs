mod run_proxy;

use log::{error, info, warn};
use rfrp_config::config_info::base_info_ops::BaseInfoGetter;
use rfrp_config::config_info::base_types::ConfigInfo;
use std::sync::Arc;

use run_proxy::run_proxy;

pub async fn rfrp_server(config: Arc<ConfigInfo>) {
    info!(
        "Running in server mode, listening on {}:{}",
        config.get_server().get_ip(),
        config.get_server().get_port()
    );

    let listener = tokio::net::TcpListener::bind(config.get_server().get_addr())
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

        // Clone only the auth_token string (cheap), not the whole config
        let auth_token = config.get_server().get_auth_token().to_string();

        tokio::task::spawn(run_proxy(socket, auth_token));
    }
}
