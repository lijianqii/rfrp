use bytes::BytesMut;
use flate2::Compression;
use rfrp_config::config_info::base_types::DataInfo;
use rfrp_proto::crypto::derive_session_key;
use rfrp_proto::frame_types::RfrpFrame;
use rfrp_proto::handshake;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const TEST_TOKEN: &str = "integration-test-secret";

async fn setup_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let client_task = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });

    let (server_stream, _) = listener.accept().await.unwrap();
    let client_stream = client_task.await.unwrap();

    (server_stream, client_stream)
}

#[tokio::test]
async fn handshake_both_sides_derive_same_key() {
    let (server_stream, client_stream) = setup_pair().await;

    let (s1, s2) = tokio::join!(
        handshake::server_handshake(server_stream, TEST_TOKEN),
        handshake::client_handshake(client_stream, TEST_TOKEN),
    );

    let (_, server_cipher) = s1.expect("server handshake failed");
    let (_, client_cipher) = s2.expect("client handshake failed");

    let data = b"secret payload";
    let encrypted = server_cipher.encrypt(data);
    let decrypted = client_cipher
        .decrypt(&encrypted)
        .expect("client must decrypt server's data");

    assert_eq!(decrypted, data);

    let encrypted2 = client_cipher.encrypt(data);
    let decrypted2 = server_cipher
        .decrypt(&encrypted2)
        .expect("server must decrypt client's data");

    assert_eq!(decrypted2, data);
}

#[tokio::test]
async fn handshake_wrong_token_produces_incompatible_keys() {
    let (server_stream, client_stream) = setup_pair().await;

    let (s1, s2) = tokio::join!(
        handshake::server_handshake(server_stream, "correct-token"),
        handshake::client_handshake(client_stream, "wrong-token"),
    );

    let (_, server_cipher) = s1.expect("server handshake failed");
    let (_, client_cipher) = s2.expect("client handshake failed");

    let data = b"secret payload";
    let encrypted = client_cipher.encrypt(data);

    let result = server_cipher.decrypt(&encrypted);
    assert!(
        result.is_err(),
        "server must NOT decrypt data encrypted with wrong token"
    );
}

#[tokio::test]
async fn handshake_then_encrypted_frame_roundtrip() {
    let (server_stream, client_stream) = setup_pair().await;

    let (s1, s2) = tokio::join!(
        handshake::server_handshake(server_stream, TEST_TOKEN),
        handshake::client_handshake(client_stream, TEST_TOKEN),
    );

    let (mut server_stream, server_cipher) = s1.expect("server handshake failed");
    let (mut client_stream, client_cipher) = s2.expect("client handshake failed");

    let frame = RfrpFrame::Data(DataInfo {
        conn_id: 42,
        proxy_id: 1,
        data: bytes::Bytes::from(b"hello over tunnel".to_vec()),
    });

    let mut buf = BytesMut::with_capacity(65536);
    let mut compress = flate2::Compress::new(Compression::fast(), false);
    let encoded_bytes =
        RfrpFrame::encode_encrypted(&frame, &client_cipher, &mut buf, &mut compress);

    client_stream.writable().await.unwrap();
    let len = encoded_bytes.len() as u32;
    client_stream.write_all(&len.to_be_bytes()).await.unwrap();
    client_stream.write_all(&encoded_bytes).await.unwrap();

    let mut len_buf = [0u8; 4];
    server_stream.read_exact(&mut len_buf).await.unwrap();
    let frame_len = u32::from_be_bytes(len_buf) as usize;

    let mut frame_buf = vec![0u8; frame_len];
    server_stream.read_exact(&mut frame_buf).await.unwrap();

    let mut recv = BytesMut::from(&frame_buf[..]);
    let mut decomp_buf = Vec::new();
    let mut decompress = flate2::Decompress::new(false);
    let decoded = RfrpFrame::decode_encrypted_bytes_mut(
        &mut recv,
        &server_cipher,
        &mut decomp_buf,
        &mut decompress,
    )
    .expect("decode failed");

    match decoded {
        RfrpFrame::Data(d) => {
            assert_eq!(d.conn_id, 42);
            assert_eq!(d.proxy_id, 1);
            assert_eq!(&d.data[..], b"hello over tunnel");
        }
        other => panic!("expected Data, got {:?}", other),
    }
}

#[tokio::test]
async fn handshake_timeout_on_no_data() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let client_task = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
    let (server_stream, _) = listener.accept().await.unwrap();
    let _client_stream = client_task.await.unwrap();

    let result = tokio::time::timeout(
        Duration::from_secs(15),
        handshake::server_handshake(server_stream, TEST_TOKEN),
    )
    .await;

    assert!(result.is_ok(), "handshake should complete (with error) within timeout");
    let inner = result.unwrap();
    assert!(inner.is_err(), "handshake must fail when client sends nothing");
}

#[tokio::test]
async fn two_handshakes_produce_different_keys() {
    let token = "same-token";

    let (s1, c1) = setup_pair().await;
    let (r1, r2) = tokio::join!(
        handshake::server_handshake(s1, token),
        handshake::client_handshake(c1, token),
    );
    let (_, cipher1_server) = r1.unwrap();
    let (_, cipher1_client) = r2.unwrap();

    let (s2, c2) = setup_pair().await;
    let (r3, r4) = tokio::join!(
        handshake::server_handshake(s2, token),
        handshake::client_handshake(c2, token),
    );
    let (_, cipher2_server) = r3.unwrap();
    let (_, cipher2_client) = r4.unwrap();

    let data = b"test";
    let enc1 = cipher1_server.encrypt(data);
    let enc2 = cipher2_server.encrypt(data);

    assert!(
        cipher1_client.decrypt(&enc1).is_ok(),
        "same connection must work"
    );
    assert!(
        cipher2_client.decrypt(&enc2).is_ok(),
        "same connection must work"
    );
    assert!(
        cipher1_client.decrypt(&enc2).is_err(),
        "cross-connection decryption must fail (different session keys)"
    );
    assert!(
        cipher2_client.decrypt(&enc1).is_err(),
        "cross-connection decryption must fail (different session keys)"
    );
}

#[test]
fn derive_session_key_tamper_resistant() {
    let cn: [u8; 32] = rand::random();
    let sn: [u8; 32] = rand::random();

    let k1 = derive_session_key("token", &cn, &sn);
    let k2 = derive_session_key("token", &cn, &sn);
    assert_eq!(k1, k2, "same inputs → same key");

    let mut cn_modified = cn;
    cn_modified[0] ^= 1;
    let k3 = derive_session_key("token", &cn_modified, &sn);
    assert_ne!(k1, k3, "single bit change in nonce → different key");

    let k4 = derive_session_key("toke", &cn, &sn);
    assert_ne!(k1, k4, "different token → different key");
}
