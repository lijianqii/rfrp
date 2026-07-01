use clap::Parser;
use log::{error, info};
use rfrp_client::rfrp_client;
use rfrp_config::config_info::base_types::ConfigInfo;
use rfrp_config::config_info::base_types::RunningMode;
use rfrp_server::rfrp_server;
use std::sync::Arc;
use tokio::runtime::Runtime;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    config: String,
}

pub fn rfrp_main() {
    let args = Args::parse();

    let configs = ConfigInfo::new(&args.config);

    configs.debug_info();

    if let Err(e) = configs.validate() {
        error!("Configuration validation failed: {}", e);
        return;
    }

    rfrp_run(configs);
}

fn rfrp_run(configs: ConfigInfo) {
    let configs = Arc::new(configs);
    match configs.get_running_mode() {
        RunningMode::Server => {
            let server = rfrp_server(Arc::clone(&configs));
            Runtime::new().unwrap().block_on(server);
        }
        RunningMode::Client => {
            info!("Running on client mode");
            let client = rfrp_client(Arc::clone(&configs));
            Runtime::new().unwrap().block_on(client);
        }
        _ => {
            error!("Can not run in mode: {:?}", configs.get_running_mode());
        }
    }
}
