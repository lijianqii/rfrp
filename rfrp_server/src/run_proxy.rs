use tokio::{io::AsyncReadExt, net::TcpStream};
use tokio::io::AsyncWriteExt;

pub async fn run_proxy(client: TcpStream) {
    let (mut reader, mut writer) = client.into_split();

    let mut buf: [u8; 1024] = [0; 1024];

    loop {
        let n = reader.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }

        writer.write_all(&buf[..n]).await.unwrap();
    }
}
