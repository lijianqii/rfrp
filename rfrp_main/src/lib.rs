use clap::Parser;
use log::{error, info};
use tokio::runtime::Runtime;
use rfrp_config::config_info::base_types::RunningMode;
use rfrp_config::config_info::base_types::ConfigInfo;
use rfrp_server::rfrp_server;
use rfrp_client::rfrp_client;

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

    rfrp_run(configs);
}

fn rfrp_run(configs: ConfigInfo) {
    match configs.get_running_mode() {
        RunningMode::Server => {
            let server = rfrp_server(configs);
            Runtime::new().unwrap().block_on(server);
        }
        RunningMode::Client => {
            info!("Running on client mode");
            let client = rfrp_client(configs);
            Runtime::new().unwrap().block_on(client);
        }
        _ => {
            error!("Can not run in mode: {:?}", configs.get_running_mode());
        }
    }
}
