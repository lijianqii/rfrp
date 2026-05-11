use log::{info, error};
use tokio::{net::TcpStream, task};
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use tokio_stream::StreamExt;
use rfrp_proto::frame_types::RfrpFrame;
use tokio::sync::mpsc;
use futures::SinkExt;
use rfrp_proto::frame_handle::handle_reg_frame;
use bytes::Bytes;

pub async fn run_proxy(client: TcpStream, auth_token: String) {
    info!("Auth token: {}", auth_token);

    let (reader, writer) = client.into_split();

    let mut reader = FramedRead::new(reader, LengthDelimitedCodec::new());
    let mut writer = FramedWrite::new(writer, LengthDelimitedCodec::new());

    let (tx_channel, mut rx_channel) = mpsc::channel::<RfrpFrame>(128);

    task::spawn(async move {
        while let Some(frame) = rx_channel.recv().await {
            let bytes = RfrpFrame::encode(&frame);
            writer.send(Bytes::from(bytes)).await.unwrap();
        }
    });

    loop {
        let frame = match reader.next().await {
            Some(frame) => {
                let bytes = frame.unwrap();
                RfrpFrame::decode(&bytes)
            },
            None => break,
        };

        match frame {
            Ok(frame) => {
                match frame {
                    RfrpFrame::Register(client_info) => {
                        info!("Client registered: {:?}", client_info);
                        task::spawn(handle_reg_frame(client_info, tx_channel.clone()));
                    },
                    RfrpFrame::Control(control_info) => {
                        info!("Control info: {:?}", control_info);
                    },
                    RfrpFrame::Data(data_info) => {
                        info!("Data info: {:?}", data_info);
                    },
                }
            },
            Err(e) => {
                error!("Decode error: {}", e);
                continue;
            },
        }
    }
}
