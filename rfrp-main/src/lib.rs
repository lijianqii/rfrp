use chrono::Local;
use clap::Parser;
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::io::Write;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::task;
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

#[derive(Serialize, Deserialize, Debug)]
enum RunningMode {
    Server,
    Client,
    Unknown,
}

#[derive(Serialize, Deserialize, Debug)]
struct ServerInfo {
    server_ip: String,
    server_port: u16,
    auth_token: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct ClientInfo {
    name: String,
    bind_port: u16,
    proxy_ip: String,
    proxy_port: u16,
    proxy_con_type: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct ConfigInfo {
    running_mode: RunningMode,
    server: ServerInfo,
    client_proxy: Vec<ClientInfo>,
}

#[derive(Serialize, Deserialize, Debug)]
struct DataInfo {
    client_info: ClientInfo,
    data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
enum RfrpFrame {
    Register(ClientInfo),
    Control,
    Data(DataInfo),
}

enum RfrpErrorCode {
    _RfrpOk = 0,
    RfrpConfigError = 1,
    RfrpRunningModeUnknown = 2,
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

    let file = match std::fs::File::open(&args.config) {
        Ok(file) => file,
        Err(e) => {
            error!("Error while loading config file: {}", e);
            std::process::exit(RfrpErrorCode::RfrpConfigError as i32);
        }
    };

    let configs: ConfigInfo = match serde_json::from_reader(file) {
        Ok(configs) => configs,
        Err(e) => {
            error!("Error while parsing config strings: {}", e);
            std::process::exit(RfrpErrorCode::RfrpConfigError as i32);
        }
    };

    rfrp_fun(configs)
}

fn rfrp_fun(configs: ConfigInfo) {
    match configs.running_mode {
        RunningMode::Server => {
            let server = rfrp_run_server(configs);
            Runtime::new().unwrap().block_on(server);
        }
        RunningMode::Client => {
            info!("Running on client mode");
            todo!() //rfrp_run_client(configs.server);
        }
        RunningMode::Unknown => {
            error!("Can not run in mode: {:?}", configs.running_mode);
            std::process::exit(RfrpErrorCode::RfrpRunningModeUnknown as i32);
        }
    }
}

async fn rfrp_run_server(configs: ConfigInfo) {
    info!(
        "Running on server mode, bind addr {}:{}",
        configs.server.server_ip, configs.server.server_port
    );

    let server = TcpListener::bind(format!(
        "{}:{}",
        configs.server.server_ip, configs.server.server_port
    ))
    .await
    .unwrap();

    loop {
        let (client, peer) = match server.accept().await {
            Ok((client, peer)) => {
                info!("Accepted connection from {}", peer);
                (client, peer)
            }
            Err(e) => {
                error!("Error while accepting connection: {}", e);
                continue;
            }
        };

        task::spawn(rfrp_run_proxy(client));
    }
}

async fn rfrp_run_proxy(client: TcpStream) {
    let (reader, writer) = client.into_split();

    let (tx_channel, rx_channel) = mpsc::channel::<RfrpFrame>(128);

    let mut reader = FramedRead::new(reader, LengthDelimitedCodec::new());
    let writer = FramedWrite::new(writer, LengthDelimitedCodec::new());

    let reg_frame: RfrpFrame =
        serde_json::from_slice(reader.next().await.unwrap().unwrap().as_ref()).unwrap();

    let bind_addr = match reg_frame {
        RfrpFrame::Register(client_info) => {
            match TcpListener::bind(format!("0.0.0.0:{}", client_info.bind_port)).await {
                Ok(listener) => {
                    info!("Bind to {}", client_info.bind_port);
                    listener
                }
                Err(e) => {
                    error!("");
                    return;
                }
            }
        }
        _ => {
            error!("First frame is not a register frame: {:?}", reg_frame);
            return;
        }
    };

    loop {
        let remote = match bind_addr.accept().await {
            Ok((remote_stream, remote_addr)) => {
                info!("Accepted connection from {}", remote_addr);
                remote_stream
            },
            Err(e) => {
                error!("Error while accepting connection: {}", e);
                continue;
            }
        };
    }
}
