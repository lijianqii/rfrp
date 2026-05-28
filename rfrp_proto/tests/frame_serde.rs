use bytes::Bytes;
use rfrp_config::config_info::base_types::{
    ClientInfo, ControlInfo, P2pSignalType,
};
use rfrp_proto::crypto::{derive_key, Cipher};
use rfrp_proto::frame_types::RfrpFrame;

// -- Frame encode/decode roundtrip tests --

#[test]
fn data_frame_roundtrip() {
    let frame = RfrpFrame::new_data_frame(Bytes::from_static(b"hello"), "ssh", 42);
    let encoded = RfrpFrame::encode(&frame);
    let decoded = RfrpFrame::decode(&encoded).unwrap();
    match decoded {
        RfrpFrame::Data(info) => {
            assert_eq!(info.conn_id, 42);
            assert_eq!(info.proxy_name, "ssh");
            assert_eq!(info.data.as_ref(), b"hello");
        }
        other => panic!("Expected Data frame, got {:?}", other),
    }
}

#[test]
fn data_frame_empty_payload() {
    let frame = RfrpFrame::new_data_frame(Bytes::new(), "rdp", 0);
    let encoded = RfrpFrame::encode(&frame);
    let decoded = RfrpFrame::decode(&encoded).unwrap();
    match decoded {
        RfrpFrame::Data(info) => {
            assert_eq!(info.conn_id, 0);
            assert!(info.data.is_empty());
        }
        other => panic!("Expected Data frame, got {:?}", other),
    }
}

#[test]
fn control_frame_roundtrip() {
    let frame = RfrpFrame::Control(ControlInfo {
        command: "test".to_string(),
        args: vec!["a".to_string(), "b".to_string()],
    });
    let encoded = RfrpFrame::encode(&frame);
    let decoded = RfrpFrame::decode(&encoded).unwrap();
    match decoded {
        RfrpFrame::Control(info) => {
            assert_eq!(info.command, "test");
            assert_eq!(info.args, vec!["a", "b"]);
        }
        other => panic!("Expected Control frame, got {:?}", other),
    }
}

#[test]
fn p2p_signal_frame_roundtrip() {
    let frame = RfrpFrame::new_p2p_signal(
        P2pSignalType::Offer,
        "peer-a",
        "peer-b",
        b"payload".to_vec(),
    );
    let encoded = RfrpFrame::encode(&frame);
    let decoded = RfrpFrame::decode(&encoded).unwrap();
    match decoded {
        RfrpFrame::P2pSignal(info) => {
            assert_eq!(info.signal_type, P2pSignalType::Offer);
            assert_eq!(info.from_client, "peer-a");
            assert_eq!(info.to_client, "peer-b");
            assert_eq!(info.payload, b"payload");
        }
        other => panic!("Expected P2pSignal frame, got {:?}", other),
    }
}

#[test]
fn register_ack_frame_roundtrip() {
    let client: ClientInfo = serde_json::from_str(
        r#"{
        "name": "ssh",
        "bind_port": 22001,
        "proxy_ip": "192.168.1.1",
        "proxy_port": 22,
        "proxy_con_type": "tcp"
    }"#,
    )
    .unwrap();
    let frame = RfrpFrame::new_reg_ack_frame(&client, true);
    let encoded = RfrpFrame::encode(&frame);
    let decoded = RfrpFrame::decode(&encoded).unwrap();
    match decoded {
        RfrpFrame::RegisterAck(resp) => {
            assert!(resp.success);
            assert_eq!(resp.client.get_name(), "ssh");
            assert_eq!(resp.client.get_bind_port(), 22001);
        }
        other => panic!("Expected RegisterAck frame, got {:?}", other),
    }
}

// -- Encrypted frame roundtrip tests --

#[test]
fn encrypted_data_frame_roundtrip() {
    let key = derive_key("test-token");
    let cipher = Cipher::new(&key);
    let frame = RfrpFrame::new_data_frame(Bytes::from_static(b"secret"), "ssh", 1);
    let encrypted = RfrpFrame::encode_encrypted(&frame, &cipher);
    let decrypted = RfrpFrame::decode_encrypted(&encrypted, &cipher).unwrap();
    match decrypted {
        RfrpFrame::Data(info) => {
            assert_eq!(info.conn_id, 1);
            assert_eq!(info.proxy_name, "ssh");
            assert_eq!(info.data.as_ref(), b"secret");
        }
        other => panic!("Expected Data frame, got {:?}", other),
    }
}

#[test]
fn encrypted_control_frame_roundtrip() {
    let key = derive_key("test-token");
    let cipher = Cipher::new(&key);
    let frame = RfrpFrame::Control(ControlInfo {
        command: "ping".to_string(),
        args: vec![],
    });
    let encrypted = RfrpFrame::encode_encrypted(&frame, &cipher);
    let decrypted = RfrpFrame::decode_encrypted(&encrypted, &cipher).unwrap();
    match decrypted {
        RfrpFrame::Control(info) => {
            assert_eq!(info.command, "ping");
            assert!(info.args.is_empty());
        }
        other => panic!("Expected Control frame, got {:?}", other),
    }
}

#[test]
fn decrypt_with_wrong_key_fails() {
    let key1 = derive_key("token-a");
    let key2 = derive_key("token-b");
    let cipher1 = Cipher::new(&key1);
    let cipher2 = Cipher::new(&key2);
    let frame = RfrpFrame::new_data_frame(Bytes::from_static(b"secret"), "ssh", 1);
    let encrypted = RfrpFrame::encode_encrypted(&frame, &cipher1);
    assert!(RfrpFrame::decode_encrypted(&encrypted, &cipher2).is_err());
}

#[test]
fn decode_invalid_bytes_fails() {
    let result = RfrpFrame::decode(&[0xFF, 0xFE, 0xFD]);
    assert!(result.is_err());
}

// -- P2P signal type variants --

#[test]
fn all_p2p_signal_types_roundtrip() {
    let types = [
        P2pSignalType::PeerQuery,
        P2pSignalType::PeerFound,
        P2pSignalType::Offer,
        P2pSignalType::Answer,
        P2pSignalType::Candidate,
        P2pSignalType::Ping,
        P2pSignalType::Pong,
    ];
    for signal_type in types {
        let frame = RfrpFrame::new_p2p_signal(signal_type.clone(), "a", "b", vec![]);
        let encoded = RfrpFrame::encode(&frame);
        let decoded = RfrpFrame::decode(&encoded).unwrap();
        match decoded {
            RfrpFrame::P2pSignal(info) => {
                assert_eq!(info.signal_type, signal_type);
            }
            other => panic!("Expected P2pSignal frame, got {:?}", other),
        }
    }
}
