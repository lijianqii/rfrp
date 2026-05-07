use chrono::Local;
use clap::Parser;
use log::{error, info};
use rfrp_config::config_info::base_info_getter::BaseInfoGetter;
use serde::{Deserialize, Serialize};
use std::io::Write;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::task;
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use rfrp_config::config_info::base_types::{ConfigInfo, ServerInfo};
use rfrp_config::config_info::base_types::ClientInfo;
use rfrp_config::config_info::base_types::RunningMode;

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

pub enum RfrpErrorCode {
    RfrpOk = 0,
    RfrpConfigError = 1,
    RfrpRunningModeUnknown = 2,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    config: String,
}

pub fn rfrp_main() -> RfrpErrorCode {
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
            return RfrpErrorCode::RfrpConfigError;
        }
    };

    let configs: ConfigInfo = match serde_json::from_reader(file) {
        Ok(configs) => configs,
        Err(e) => {
            error!("Error while parsing config strings: {}", e);
            return RfrpErrorCode::RfrpConfigError;
        }
    };

    rfrp_fun(configs);

    return RfrpErrorCode::RfrpOk;
}

fn rfrp_fun(configs: ConfigInfo) {
    match configs.running_mode {
        RunningMode::Server => {
            let server = rfrp_run_server(configs.server);
            Runtime::new().unwrap().block_on(server);
        }
        RunningMode::Client => {
            info!("Running on client mode");
            todo!() //rfrp_run_client(configs.server);
        }
        _ => {
            error!("Can not run in mode: {:?}", configs.running_mode);
            std::process::exit(RfrpErrorCode::RfrpRunningModeUnknown as i32);
        }
    }
}

async fn rfrp_run_server(server: ServerInfo) {
    info!(
        "Running on server mode, bind addr {}:{}",
        server.get_ip(), server.get_port()
    );

    let server = TcpListener::bind(format!(
        "{}:{}",
        server.get_ip(), server.get_port()
    ))
    .await
    .unwrap();

    loop {
        let (client, peer) = match server.accept().await {
            Ok((client, peer)) => {
                (client, peer)
            }
            Err(e) => {
                error!("Error while accepting connection: {}", e);
                continue;
            }
        };

        info!("Accepted connection from {}", peer);

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
            match TcpListener::bind(format!("0.0.0.0:{}", client_info.get_bind_port())).await {
                Ok(listener) => {
                    info!("Bind to {}", client_info.get_bind_port());
                    listener
                }
                Err(e) => {
                    error!("Bind to [{}] failed, please check your port: {}", client_info.get_bind_port(), e);
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
        // 这里处理接收到了请求之后的处理，应该通过tx_channel把数据帧放到队列里面，然后发出去，再由rx_channel接收到了之后发到对端
        task::spawn(async move {
            // 把对端的接收和发送分开处理
        });
    }
}
