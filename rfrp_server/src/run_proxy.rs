use log::info;
use tokio::net::TcpStream;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use tokio_stream::StreamExt;
use rfrp_proto::frame_types::RfrpFrame;
use tokio::sync::mpsc;

pub async fn run_proxy(client: TcpStream, auth_token: String) {
    info!("Auth token: {}", auth_token);

    let (mut reader, mut writer) = client.into_split();

    let mut reader = FramedRead::new(reader, LengthDelimitedCodec::new());
    let mut writer = FramedWrite::new(writer, LengthDelimitedCodec::new());

    let (tx_channel, rx_channel) = mpsc::channel::<RfrpFrame>(128);

    let mut buf: [u8; 1024] = [0; 1024];

    loop {
        // let n = reader.read(&mut buf).await.unwrap();
        // if n == 0 {
        //     break;
        // }

        // writer.write_all(&buf[..n]).await.unwrap();
    }
}
