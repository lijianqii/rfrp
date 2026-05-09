use log::{error, info};
use rfrp_config::config_info::base_types::ClientInfo;
use tokio::{net::TcpListener, sync::mpsc::Sender};

use crate::frame_types::RfrpFrame;

pub async fn handle_reg_frame(client_info: ClientInfo, tx_channel: Sender<RfrpFrame>) {
    let proxyer = match TcpListener::bind(format!("0.0.0.0:{}", client_info.get_bind_port())).await {
        Ok(listener) => {
            info!("Proxyer {} bound to port {}", client_info.get_name(), client_info.get_bind_port());
            listener
        },
        Err(e) => {
            error!("Failed to bind proxyer: {}", e);
            return;
        }
    };

    loop {
        let (remote, peer) = match proxyer.accept().await {
            Ok((remote, peer)) => (remote, peer),
            Err(e) => {
                error!("Failed to accept connection: {}", e);
                continue;
            }
        };
        info!("Accepted connection from {}", peer);

    }
}
