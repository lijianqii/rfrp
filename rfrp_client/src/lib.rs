mod run_proxy;

use log::{info, warn};
use rfrp_config::config_info::{base_info_ops::BaseInfoGetter, base_types::ConfigInfo};
use rfrp_proto::crypto::{self, Cipher};
use run_proxy::run_proxy;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;

/// Maximum delay between reconnection attempts (in seconds).
const MAX_RECONNECT_DELAY: u64 = 60;
/// Initial delay for the first reconnection attempt (in seconds).
const INITIAL_RECONNECT_DELAY: u64 = 3;

pub async fn rfrp_client(config: Arc<ConfigInfo>) {
    // Derive key and cipher once — reused across all reconnections.
    // This avoids recomputing SHA-256 + AES key schedule on every reconnect.
    let key = crypto::derive_key(config.get_server().get_auth_token());
    let cipher = Arc::new(Cipher::new(&key));

    let mut attempt: u32 = 0;

    loop {
        attempt += 1;

        let server_addr = config.get_server().get_addr();
        info!(
            "Connecting to server at {} (attempt {})...",
            server_addr, attempt
        );

        let remote = match TcpStream::connect(server_addr).await {
            Ok(stream) => {
                info!("Connected to server at {}", server_addr);
                stream
            }
            Err(e) => {
                let delay = calc_reconnect_delay(attempt);
                warn!(
                    "Failed to connect to server: {}. Retrying in {} seconds...",
                    e,
                    delay.as_secs()
                );
                tokio::time::sleep(delay).await;
                continue;
            }
        };

        // Run the proxy session. This returns when the connection drops.
        // Pass Arc references — no cloning of config or cipher needed.
        run_proxy(remote, Arc::clone(&config), Arc::clone(&cipher)).await;

        // If we get here, the connection was lost. Reset attempt counter
        // for the next connection (but keep a small delay).
        warn!("Connection to server lost. Reconnecting...");
        let delay = calc_reconnect_delay(attempt);
        tokio::time::sleep(delay).await;
    }
}

/// Calculate reconnection delay with exponential backoff, capped at MAX_RECONNECT_DELAY.
fn calc_reconnect_delay(attempt: u32) -> Duration {
    let seconds = (INITIAL_RECONNECT_DELAY as u64)
        .saturating_mul(2u64.saturating_pow(attempt.saturating_sub(1)))
        .min(MAX_RECONNECT_DELAY);
    Duration::from_secs(seconds)
}
