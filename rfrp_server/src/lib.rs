mod run_proxy;

use rfrp_config::config_info::base_types::ServerInfo;
use rfrp_config::config_info::base_info_getter::BaseInfoGetter;
use log::info;
use log::error;

use run_proxy::run_proxy;

pub async fn rfrp_server(server: ServerInfo) {
    info!("Running in server mode, listening on {}:{}", server.get_ip(), server.get_port());

    let listener = tokio::net::TcpListener::bind(&server.get_addr()).await.unwrap();
    loop {
        let (socket, peer) = match listener.accept().await {
            Ok((socket, peer)) => {
                (socket, peer)
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
                continue;
            }
        };
        info!("Accepted connection from {}", peer);

        tokio::task::spawn(run_proxy(socket));
    }
}
