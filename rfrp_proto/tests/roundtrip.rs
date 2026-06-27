use bytes::BytesMut;
use flate2::Compression;
use rfrp_config::config_info::base_types::{ClientInfo, DataInfo};
use rfrp_proto::crypto::{Cipher, derive_key};
use rfrp_proto::frame_types::RfrpFrame;

fn make_cipher() -> Cipher {
    Cipher::new(&derive_key("testtoken"))
}

fn make_client_info() -> ClientInfo {
    // ClientInfo fields are private; construct via its public Deserialize + init.
    // We build a minimal ConfigInfo JSON and extract the single client_proxy entry.
    let json = r#"{
        "running_mode": "Client",
        "server": { "server_ip": "127.0.0.1", "server_port": 11000, "auth_token": "t" },
        "client_proxy": [{
            "name": "echo", "bind_port": 22001,
            "proxy_ip": "127.0.0.1", "proxy_port": 9022, "proxy_con_type": "tcp"
        }]
    }"#;
    let configs: rfrp_config::config_info::base_types::ConfigInfo =
        serde_json::from_str(json).unwrap();
    let configs = configs.init();
    configs.get_client_proxy()[0].clone()
}

#[test]
fn diag_compress_decompress_roundtrip() {
    // Isolate the compress/decompress layer to see if it is the culprit.
    use rfrp_proto::compress;
    let original: Vec<u8> = (0..200u32).flat_map(|i| i.to_le_bytes()).collect();

    let mut dst = BytesMut::with_capacity(65536);
    let mut compress = flate2::Compress::new(Compression::fast(), false);
    compress::compress_into_bytes_mut(&original, &mut dst, &mut compress);
    let compressed = dst.split().freeze();

    let mut decomp_buf = Vec::new();
    let mut decompress = flate2::Decompress::new(false);
    compress::decompress_into_vec(&compressed, &mut decomp_buf, &mut decompress)
        .expect("decompress failed");

    println!(
        "original len={}, compressed len={}, decompressed len={}",
        original.len(),
        compressed.len(),
        decomp_buf.len()
    );
    assert_eq!(decomp_buf, original, "decompressed != original");
    println!("PASS: compress/decompress roundtrip OK");
}

#[test]
fn diag_crypto_roundtrip() {
    // Isolate the AES-GCM layer.
    let cipher = make_cipher();
    let plaintext = b"hello rfrp crypto layer";
    let mut buf: Vec<u8> = plaintext.to_vec();
    cipher.encrypt_in_place(&mut buf);
    println!(
        "plaintext len={}, ciphertext+nonce+tag len={}",
        plaintext.len(),
        buf.len()
    );
    let pt = cipher.decrypt_in_place(&mut buf).expect("decrypt failed");
    assert_eq!(pt, plaintext);
    println!("PASS: crypto roundtrip OK");
}

#[test]
fn diag_msgpack_register_roundtrip() {
    // Isolate the MessagePack (de)serialization layer, no crypto/compress.
    let ci = make_client_info();
    let frame = RfrpFrame::Register(ci);
    let encoded = RfrpFrame::encode(&frame);
    println!("msgpack encoded len={}", encoded.len());
    let decoded = RfrpFrame::decode(&encoded).expect("decode failed");
    match decoded {
        RfrpFrame::Register(c) => {
            assert_eq!(c.get_name(), "echo");
            println!("PASS: msgpack register roundtrip OK");
        }
        other => panic!("expected Register, got {:?}", other),
    }
}

#[test]
fn roundtrip_register_frame() {
    let cipher = make_cipher();
    let frame = RfrpFrame::Register(make_client_info());

    let mut buf = BytesMut::with_capacity(65536);
    let mut compress = flate2::Compress::new(Compression::fast(), false);
    let bytes = RfrpFrame::encode_encrypted(&frame, &cipher, &mut buf, &mut compress);

    // Simulate what the server does: receive BytesMut from the codec.
    let mut recv = BytesMut::from(&bytes[..]);
    let mut decomp_buf = Vec::new();
    let mut decompress = flate2::Decompress::new(false);
    let decoded =
        RfrpFrame::decode_encrypted_bytes_mut(&mut recv, &cipher, &mut decomp_buf, &mut decompress);

    match decoded {
        Ok(RfrpFrame::Register(ci)) => {
            assert_eq!(ci.get_name(), "echo");
            assert_eq!(ci.get_bind_port(), 22001);
            println!("PASS: register roundtrip OK");
        }
        other => panic!(
            "expected Register, got {:?}",
            other.map(|f| format!("{:?}", f))
        ),
    }
}

#[test]
fn roundtrip_multiple_frames_reuse_compressor() {
    // The hot path reuses Compress/Decompress across frames. Verify that
    // reusing them doesn't corrupt subsequent frames (a likely root cause
    // of "failed to fill whole buffer" on the server).
    let cipher = make_cipher();
    let mut buf = BytesMut::with_capacity(65536);
    let mut compress = flate2::Compress::new(Compression::fast(), false);
    let mut decomp_buf = Vec::new();
    let mut decompress = flate2::Decompress::new(false);

    for i in 0..5u32 {
        let frame = RfrpFrame::Data(DataInfo {
            conn_id: i as u64,
            proxy_id: i,
            data: bytes::Bytes::from(format!("payload-{}", i)),
        });
        let bytes = RfrpFrame::encode_encrypted(&frame, &cipher, &mut buf, &mut compress);
        let mut recv = BytesMut::from(&bytes[..]);
        let decoded = RfrpFrame::decode_encrypted_bytes_mut(
            &mut recv,
            &cipher,
            &mut decomp_buf,
            &mut decompress,
        )
        .unwrap_or_else(|_| panic!("decode failed on frame {}", i));
        match decoded {
            RfrpFrame::Data(d) => {
                assert_eq!(d.conn_id, i as u64);
                assert_eq!(d.proxy_id, i);
                assert_eq!(&d.data[..], format!("payload-{}", i).as_bytes());
            }
            other => panic!("frame {}: expected Data, got {:?}", i, other),
        }
    }
    println!("PASS: multi-frame reuse roundtrip OK");
}

#[test]
fn roundtrip_heartbeat_frames() {
    // Verify that ping/pong Control frames survive the full encode → encrypt →
    // compress → decrypt → decompress → decode pipeline, and that the
    // is_ping / is_pong helpers correctly identify them.
    let cipher = make_cipher();
    let mut buf = BytesMut::with_capacity(65536);
    let mut compress = flate2::Compress::new(Compression::fast(), false);
    let mut decomp_buf = Vec::new();
    let mut decompress = flate2::Decompress::new(false);

    // Ping roundtrip
    let ping = RfrpFrame::new_ping_frame();
    assert!(ping.is_ping());
    assert!(!ping.is_pong());

    let bytes = RfrpFrame::encode_encrypted(&ping, &cipher, &mut buf, &mut compress);
    let mut recv = BytesMut::from(&bytes[..]);
    let decoded =
        RfrpFrame::decode_encrypted_bytes_mut(&mut recv, &cipher, &mut decomp_buf, &mut decompress)
            .expect("ping decode failed");

    assert!(decoded.is_ping(), "decoded frame should be a ping");
    assert!(!decoded.is_pong());

    // Pong roundtrip
    let pong = RfrpFrame::new_pong_frame();
    assert!(!pong.is_ping());
    assert!(pong.is_pong());

    let bytes = RfrpFrame::encode_encrypted(&pong, &cipher, &mut buf, &mut compress);
    let mut recv = BytesMut::from(&bytes[..]);
    let decoded =
        RfrpFrame::decode_encrypted_bytes_mut(&mut recv, &cipher, &mut decomp_buf, &mut decompress)
            .expect("pong decode failed");

    assert!(!decoded.is_ping());
    assert!(decoded.is_pong(), "decoded frame should be a pong");

    println!("PASS: heartbeat ping/pong roundtrip OK");
}
