use bytes::BytesMut;
use flate2::Compression;
use rfrp_config::config_info::base_types::{ClientInfo, DataInfo};
use rfrp_proto::crypto::{Cipher, derive_key, derive_session_key};
use rfrp_proto::compress::{self, MAX_DECOMPRESSED_SIZE};
use rfrp_proto::frame_types::RfrpFrame;

fn make_cipher() -> Cipher {
    Cipher::new(&derive_key("testtoken"))
}

fn make_client_info() -> ClientInfo {
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
    let cipher = make_cipher();
    let mut buf = BytesMut::with_capacity(65536);
    let mut compress = flate2::Compress::new(Compression::fast(), false);
    let mut decomp_buf = Vec::new();
    let mut decompress = flate2::Decompress::new(false);

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

// ─── Security fixes tests ───

#[test]
fn nonce_uniqueness_across_reconnects() {
    // Simulate reconnection: same auth_token, different session keys
    let token = "mytoken";

    // Connection 1
    let cn1: [u8; 32] = rand::random();
    let sn1: [u8; 32] = rand::random();
    let key1 = derive_session_key(token, &cn1, &sn1);
    let c1 = Cipher::new(&key1);

    // Connection 2 (reconnect)
    let cn2: [u8; 32] = rand::random();
    let sn2: [u8; 32] = rand::random();
    let key2 = derive_session_key(token, &cn2, &sn2);
    let c2 = Cipher::new(&key2);

    assert_ne!(key1, key2, "session keys must differ across connections");

    let data = b"test data";
    let enc1 = c1.encrypt(data);
    let enc2 = c2.encrypt(data);

    // Decrypt each with its own cipher must succeed
    let dec1 = c1.decrypt(&enc1).expect("c1 decrypt");
    let dec2 = c2.decrypt(&enc2).expect("c2 decrypt");
    assert_eq!(dec1, data);
    assert_eq!(dec2, data);

    // Decrypting c2's ciphertext with c1 must fail (different keys)
    assert!(
        c1.decrypt(&enc2).is_err(),
        "cross-connection decryption must fail (different session keys)"
    );

    println!("PASS: nonce uniqueness across reconnects OK");
}

#[test]
fn session_key_symmetric_derivation() {
    let token = "shared-secret";
    let client_nonce: [u8; 32] = [0xAA; 32];
    let server_nonce: [u8; 32] = [0xBB; 32];

    let key_client = derive_session_key(token, &client_nonce, &server_nonce);
    let key_server = derive_session_key(token, &client_nonce, &server_nonce);

    assert_eq!(key_client, key_server, "both sides must derive same key");

    // Different order should produce different key
    let key_reversed = derive_session_key(token, &server_nonce, &client_nonce);
    assert_ne!(key_client, key_reversed, "order must matter");

    println!("PASS: session key symmetry OK");
}

#[test]
fn handshake_key_different_per_nonce() {
    let token = "secret";
    let cn: [u8; 32] = rand::random();
    let sn: [u8; 32] = rand::random();

    let key1 = derive_session_key(token, &cn, &sn);
    let key2 = derive_session_key(token, &sn, &cn); // swapped
    assert_ne!(key1, key2, "swapped nonces produce different keys");

    let key3 = derive_session_key("wrong", &cn, &sn);
    assert_ne!(key1, key3, "different token produces different key");

    println!("PASS: handshake key uniqueness OK");
}

#[test]
fn decompression_bomb_detected() {
    use flate2::{Compress, Decompress, Compression, FlushCompress};

    // Create a highly compressible payload (all zeros) that decompresses large
    let original = vec![0u8; 1024 * 1024]; // 1 MB of zeros

    let mut compressed = Vec::new();
    {
        let mut c = Compress::new(Compression::best(), false);
        let mut buf = [0u8; 8192];
        let mut input = &original[..];
        loop {
            let before_in = c.total_in();
            let status = c.compress(input, &mut buf, FlushCompress::Finish).unwrap();
            let consumed = (c.total_in() - before_in) as usize;
            compressed.extend_from_slice(&buf[..(c.total_out() as usize - compressed.len())]);
            input = &input[consumed..];
            if status == flate2::Status::StreamEnd {
                break;
            }
        }
    }

    println!("1MB zeros compressed to {} bytes", compressed.len());
    assert!(compressed.len() < 2000, "zeros should compress well (got {})", compressed.len());

    // Decompress without limit — should succeed
    let mut decomp_buf = Vec::new();
    let mut d = Decompress::new(false);
    assert!(compress::decompress_into_vec(&compressed, &mut decomp_buf, &mut d).is_ok());
    assert_eq!(decomp_buf.len(), original.len());

    // Now test that a payload exceeding the limit is rejected.
    // We create a valid DEFLATE stream that decompresses to a bit over MAX_DECOMPRESSED_SIZE.
    // Strategy: compress a large zero-payload, then decompress — the built-in limit
    // in decompress_into_vec will catch it.
    let huge = vec![0u8; MAX_DECOMPRESSED_SIZE + 1024];
    let mut huge_compressed = Vec::new();
    {
        let mut c = Compress::new(Compression::best(), false);
        let mut buf = [0u8; 8192];
        let mut input = &huge[..];
        loop {
            let before_in = c.total_in();
            let before_out = c.total_out();
            let status = c.compress(input, &mut buf, FlushCompress::Finish).unwrap();
            let consumed = (c.total_in() - before_in) as usize;
            let written = (c.total_out() - before_out) as usize;
            huge_compressed.extend_from_slice(&buf[..written]);
            input = &input[consumed..];
            if status == flate2::Status::StreamEnd {
                break;
            }
        }
    }

    let mut bomb_buf = Vec::new();
    let mut d2 = Decompress::new(false);
    let result = compress::decompress_into_vec(&huge_compressed, &mut bomb_buf, &mut d2);
    assert!(result.is_err(), "decompression bomb must be rejected");
    assert!(
        result.unwrap_err().contains("Decompression bomb"),
        "error must mention decompression bomb"
    );

    println!("PASS: decompression bomb detection OK");
}

#[test]
fn decompress_valid_payload_still_works() {
    // Verify that the size limit doesn't break legitimate decompression
    use flate2::{Compress, Decompress, Compression, FlushCompress};

    let payload = b"hello world this is a legitimate rfrp data frame payload";
    let mut compressed = Vec::new();
    {
        let mut c = Compress::new(Compression::fast(), false);
        let mut buf = [0u8; 8192];
        let mut input: &[u8] = payload;
        loop {
            let before_in = c.total_in();
            let before_out = c.total_out();
            let status = c.compress(input, &mut buf, FlushCompress::Finish).unwrap();
            let consumed = (c.total_in() - before_in) as usize;
            let written = (c.total_out() - before_out) as usize;
            compressed.extend_from_slice(&buf[..written]);
            input = &input[consumed..];
            if status == flate2::Status::StreamEnd {
                break;
            }
        }
    }

    let mut decomp_buf = Vec::new();
    let mut d = Decompress::new(false);
    compress::decompress_into_vec(&compressed, &mut decomp_buf, &mut d).expect("decompress failed");
    assert_eq!(&decomp_buf[..], &payload[..]);

    println!("PASS: legitimate decompression still works OK");
}
