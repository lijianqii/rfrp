use rfrp_proto::frame_types::RfrpFrame;
use tokio::net::TcpStream;
use log::{debug, error, info};
use rfrp_config::config_info::base_types::ConfigInfo;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use bytes::Bytes;
use futures::SinkExt;
use tokio_stream::StreamExt;

pub async fn run_proxy(remote: TcpStream, config: ConfigInfo) {
    let (reader, writer) = remote.into_split();

    let mut reader = FramedRead::new(reader, LengthDelimitedCodec::new());
    let mut writer = FramedWrite::new(writer, LengthDelimitedCodec::new());

    for client_info in config.get_client_proxy() {
        debug!("Registering client: {:?}", client_info);

        let reg_frame = RfrpFrame::new_reg_frame(&client_info, false);
        let bytes = RfrpFrame::encode(&reg_frame);

        writer.send(Bytes::from(bytes)).await.unwrap();

        let reg_resp_frame: RfrpFrame = match reader.next().await {
            Some(frame) => {
                let bytes = frame.unwrap();
                RfrpFrame::decode(&bytes).unwrap()
            },
            None => {
                error!("Proxy {} reg failed.", client_info.get_name());
                continue;
            },
        };

        match reg_resp_frame {
            RfrpFrame::Register(client) => {
                if client.is_registed() {
                    info!("Registed client proxy: {:?}", client_info.get_name());
                } else {
                    error!("Proxy {} reg failed.", client_info.get_name());
                    continue;
                }
            }
            _ => {
                error!("Proxy {} reg failed.", client_info.get_name());
                continue;
            }
        }
    }
}
