use log::{error, info};
use rfrp_config::config_info::base_types::ClientInfo;
use tokio::{net::TcpListener, sync::mpsc::Sender, task};
use tokio::io::AsyncReadExt;

use crate::frame_types::RfrpFrame;

pub async fn handle_reg_frame(client_info: ClientInfo, tx_channel: Sender<RfrpFrame>) {
    let proxyer = match TcpListener::bind(format!("0.0.0.0:{}", client_info.get_bind_port())).await {
        Ok(listener) => {
            info!("Proxyer {} bind to port {}", client_info.get_name(), client_info.get_bind_port());
            listener
        },
        Err(e) => {
            error!("Failed to bind proxyer: {}", e);
            return;
        }
    };

    let confirm_reg = RfrpFrame::new_reg_frame(&client_info);
    tx_channel.send(confirm_reg).await.unwrap();

    loop {
        let (mut remote, peer) = match proxyer.accept().await {
            Ok((remote, peer)) => (remote, peer),
            Err(e) => {
                error!("Failed to accept connection: {}", e);
                continue;
            }
        };
        info!("Accepted connection from {}", peer);

        let client_info = client_info.clone();
        let tx_channel = tx_channel.clone();

        task::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                let n = match remote.read(&mut buf).await {
                    Ok(n) => n,
                    Err(e) => {
                        error!("Failed to read from remote: {}", e);
                        break;
                    }
                };
                if n == 0 {
                    info!("Remote closed {}", peer);
                    break;
                }
                let frame = RfrpFrame::new_data_frame(&buf[..n], &client_info);
                tx_channel.send(frame).await.unwrap();
            }
        });
    }
}
