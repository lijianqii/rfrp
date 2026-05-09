mod run_proxy;

use rfrp_config::config_info::base_types::ConfigInfo;
use rfrp_config::config_info::base_info_ops::BaseInfoGetter;
use log::info;
use log::error;

use run_proxy::run_proxy;

pub async fn rfrp_server(config: ConfigInfo) {
    info!("Running in server mode, listening on {}:{}", config.get_server().get_ip(), config.get_server().get_port());

    let listener = tokio::net::TcpListener::bind(&config.get_server().get_addr()).await.unwrap();
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

        let mut auth_token = String::new();

        auth_token.push_str(config.get_server().get_auth_token());

        tokio::task::spawn(run_proxy(socket, auth_token));
    }
}
