mod run_proxy;

use log::{error, info, warn};
use rfrp_config::config_info::base_info_ops::BaseInfoGetter;
use rfrp_config::config_info::base_types::ConfigInfo;
use std::sync::Arc;
use tokio::sync::Semaphore;

use run_proxy::run_proxy;

/// Maximum number of concurrent client control connections.
/// Each connection spawns a `run_proxy` task that allocates cipher state,
/// channels, and buffers — an attacker opening thousands of connections
/// can exhaust server memory. This semaphore caps that.
const MAX_CONCURRENT_CLIENTS: usize = 64;

pub async fn rfrp_server(config: Arc<ConfigInfo>) {
    info!(
        "Running in server mode, listening on {}:{}",
        config.get_server().get_ip(),
        config.get_server().get_port()
    );

    let listener = tokio::net::TcpListener::bind(config.get_server().get_addr())
        .await
        .unwrap();

    // Cap concurrent client connections to prevent resource exhaustion DoS.
    // When the limit is reached, new connections wait for a permit to free up.
    let connection_limit = Arc::new(Semaphore::new(MAX_CONCURRENT_CLIENTS));

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

        let permit = Arc::clone(&connection_limit);
        tokio::task::spawn(async move {
            // Acquire a permit before processing — blocks (asynchronously)
            // if at capacity, giving backpressure instead of OOM.
            let _permit = match permit.acquire_owned().await {
                Ok(p) => p,
                Err(_) => {
                    warn!("Connection limit semaphore closed, rejecting connection from {}", peer);
                    return;
                }
            };
            run_proxy(socket, auth_token).await;
            // permit is released here when _permit is dropped
        });
    }
}
