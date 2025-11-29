use chrono::Local;
use clap::Parser;
use log::{error, info, trace};
use serde_json::Value;
use std::io::Write;
use tokio::io::{AsyncReadExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use tokio::task;

const RFRP_SERVER_IP: &str = "server_ip";
const RFRP_SERVER_PORT: &str = "server_port";
const RFRP_AUTH_TOKEN: &str = "auth_token";

const RFRP_CLIENT_PROXY: &str = "client_proxy";

const RFRP_PROXY_NAME: &str = "name";
const RFRP_BIND_PORT: &str = "bind_port";
const RFRP_PROXY_IP: &str = "proxy_ip";
const RFRP_PROXY_PORT: &str = "proxy_port";
const RFRP_PROXY_CON_TYPE: &str = "proxy_con_type";

const RFRP_RUNNING_MODE: &str = "running_mode";

enum RunningMode {
    Server,
    Client,
    Unknown
}

struct ServerInfo {
    server_ip: String,
    server_port: u16,
    auth_token: String,
}

struct ClientInfo {
    name: String,
    bind_port: u16,
    proxy_ip: String,
    proxy_port: u16,
    proxy_con_type: String,
}

struct ConfigInfo {
    server: ServerInfo,
    clients: Vec<ClientInfo>,
    config_path: String,
    running_mode: RunningMode,
}

impl ConfigInfo {
    fn get_proxy_clients_count(&self) -> usize {
        self.clients.len()
    }
}

impl ConfigInfo {
    fn load_config(config_path: String) -> Self {
        trace!("Loading config from [{}]", config_path);

        let contents = match std::fs::read_to_string(&config_path) {
            Ok(contents) => contents,
            Err(e) => {
                error!("Failed read config file.");
                panic!("Error: {}", e);
            }
        };

        let configs: Value = serde_json::from_str(contents.as_str()).unwrap();

        let server_info = ServerInfo {
            server_ip: configs[RFRP_SERVER_IP].as_str().unwrap().to_string(),
            server_port: configs[RFRP_SERVER_PORT].as_u64().unwrap() as u16,
            auth_token: configs[RFRP_AUTH_TOKEN].as_str().unwrap().to_string(),
        };

        trace!("Server info: {}:{}", server_info.server_ip, server_info.server_port);

        let running_mode = match configs[RFRP_RUNNING_MODE].as_str().unwrap() {
            "server" => RunningMode::Server,
            "client" => RunningMode::Client,
            _ => {
                error!("Unknown running mode: {}", configs[RFRP_RUNNING_MODE].as_str().unwrap());
                RunningMode::Unknown
            }
        };

        trace!("Running mode: {}", match running_mode {
            RunningMode::Server => "server",
            RunningMode::Client => "client",
            RunningMode::Unknown => "invalid running mode"
        });

        let auth_token = configs[RFRP_AUTH_TOKEN].as_str().unwrap().to_string();

        let mut clients_vec = vec![];
        for client in configs[RFRP_CLIENT_PROXY].as_array().unwrap() {
            clients_vec.push(ClientInfo {
                name: client[RFRP_PROXY_NAME].as_str().unwrap().to_string(),
                bind_port: client[RFRP_BIND_PORT].as_u64().unwrap() as u16,
                proxy_ip: client[RFRP_PROXY_IP].as_str().unwrap().to_string(),
                proxy_port: client[RFRP_PROXY_PORT].as_u64().unwrap() as u16,
                proxy_con_type: client[RFRP_PROXY_CON_TYPE].as_str().unwrap().to_string(),
            })
        };

        for client in &clients_vec {
            trace!("Client: [{}] proxy {}:{} <=> {} via {}",
                client.name, client.proxy_ip,
                client.proxy_port, client.bind_port,
                client.proxy_con_type);
        }

        ConfigInfo {
            server: server_info,
            clients: clients_vec,
            config_path: config_path,
            running_mode: running_mode,
        }
    }
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    config: String,
}

pub fn rfrp_main() {
    env_logger::Builder::new()
        .filter(None, log::LevelFilter::Trace)
        .write_style(env_logger::WriteStyle::Always)
        .format(|buf, record| {
            writeln!(
                buf,
                "{} | {:>6} | {}:{:<4} | {} | - {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                record.file().unwrap_or(""),
                record.line().unwrap_or(0),
                record.module_path().unwrap_or(""),
                record.args()
            )
        })
        .init();

    let args = Args::parse();

    let config_info = ConfigInfo::load_config(args.config);

    rfrp_run(config_info);
}

fn rfrp_run(config: ConfigInfo) {
    match config.running_mode {
        RunningMode::Server => {
            info!("Running as server mode");
            let server = rfrp_run_server(config);
            let rt = Runtime::new().unwrap();

            rt.block_on(server);
        }
        RunningMode::Client => {
            info!("Running as client mode");
            //rfrp_run_client(config);
        }
        RunningMode::Unknown => {
            error!("Cannot run unknown mode");
            panic!("Unknown mode");
        }
    }
}

async fn rfrp_run_server(config: ConfigInfo) {
    let bind_addr = format!("{}:{}", config.server.server_ip, config.server.server_port);

    trace!("Binding to: {}", bind_addr);

    let server = TcpListener::bind(bind_addr).await.unwrap();

    loop {
        let (socket, peer) = server.accept().await.unwrap();
        trace!("Client connected: {}", peer);

        task::spawn(process_server(socket));
    }
}

async fn process_server(mut client: TcpStream) {
    let mut buf = [0u8; 1024];
    loop {
        match client.read(&mut buf).await {
            Ok(n) => {
                if n == 0 {
                    info!("Client {} disconnected", client.peer_addr().unwrap());
                    break;
                } else {
                    info!("Client {} read: {} bytes", client.peer_addr().unwrap(), n);
                }
            }
            Err(e) => {
                error!("Error reading from client: {}", e);
                break;
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
    }
}
