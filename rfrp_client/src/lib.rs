mod run_proxy;

use log::{error, info};
use rfrp_config::config_info::{base_info_ops::BaseInfoGetter, base_types::ConfigInfo};
use tokio::net::TcpStream;
use std::time::Duration;
use run_proxy::run_proxy;

pub async fn rfrp_client(config: ConfigInfo) {
    let remote = loop {
        match TcpStream::connect(config.get_server().get_addr()).await {
            Ok(stream) => break stream,
            Err(e) => {
                error!(
                    "Failed to connect to {}, retrying in 3 seconds: {}",
                    config.get_server().get_addr(),
                    e
                );
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        }
    };

    info!("Connected to server: {}", config.get_server().get_addr());

    run_proxy(remote, config).await;
}
