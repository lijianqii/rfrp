use super::*;

// -- XOR-MAPPED-ADDRESS tests --

#[test]
fn xor_mapped_ipv4_basic() {
    // Target: 192.168.1.1:8080
    // xport = 8080 ^ 0x2112 = 0x1F90 ^ 0x2112 = 0x3E82
    // xip   = 0xC0A80101 ^ 0x2112A442 = 0xE1BAA543
    // data[0]=0x00(reserved), data[1]=0x01(family IPv4)
    let data: [u8; 8] = [0x00, 0x01, 0x3E, 0x82, 0xE1, 0xBA, 0xA5, 0x43];
    let addr = parse_xor_mapped_address(&data).unwrap();
    assert_eq!(addr, "192.168.1.1:8080".parse::<SocketAddr>().unwrap());
}

#[test]
fn xor_mapped_ipv4_loopback() {
    // Target: 127.0.0.1:3478
    // 3478 = 0x0D96, xport = 0x0D96 ^ 0x2112 = 0x2C84
    // 0x7F000001 ^ 0x2112A442 = 0x5E12A443
    let data: [u8; 8] = [0x00, 0x01, 0x2C, 0x84, 0x5E, 0x12, 0xA4, 0x43];
    let addr = parse_xor_mapped_address(&data).unwrap();
    assert_eq!(addr, "127.0.0.1:3478".parse::<SocketAddr>().unwrap());
}

#[test]
fn xor_mapped_ipv6_loopback() {
    // Target: ::1 port 8080
    // xport = 0x3E82 (same as IPv4)
    // IP ::1 = [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1]
    // XOR mask: [0x21,0x12,0xA4,0x42, 0,0,0,0, 0,0,0,0, 0,0,0,0]
    // Result:   [0x21,0x12,0xA4,0x42, 0,0,0,0, 0,0,0,0, 0,0,0,1]
    let data: [u8; 20] = [
        0x00, 0x02, 0x3E, 0x82, 0x21, 0x12, 0xA4, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];
    let addr = parse_xor_mapped_address(&data).unwrap();
    assert_eq!(addr, "[::1]:8080".parse::<SocketAddr>().unwrap());
}

#[test]
fn xor_mapped_ipv6_global() {
    // Target: fe80::1 port 8080
    // fe80::1 = [0xfe,0x80,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1]
    // XOR with [0x21,0x12,0xA4,0x42, 0,...,0]
    // = [0xDF,0x92,0xA4,0x42, 0,0,0,0, 0,0,0,0, 0,0,0,1]
    let data: [u8; 20] = [
        0x00, 0x02, 0x3E, 0x82, 0xDF, 0x92, 0xA4, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];
    let addr = parse_xor_mapped_address(&data).unwrap();
    assert_eq!(addr, "[fe80::1]:8080".parse::<SocketAddr>().unwrap());
}

#[test]
fn xor_mapped_too_short() {
    assert!(parse_xor_mapped_address(&[0x01, 0x00, 0x00]).is_none());
}

#[test]
fn xor_mapped_unknown_family() {
    let data: [u8; 8] = [0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert!(parse_xor_mapped_address(&data).is_none());
}

#[test]
fn xor_mapped_ipv6_insufficient_data() {
    // Family 0x02 but only 8 bytes (need 20)
    let data: [u8; 8] = [0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert!(parse_xor_mapped_address(&data).is_none());
}

// -- MAPPED-ADDRESS tests --

#[test]
fn mapped_ipv4_basic() {
    // Target: 10.0.0.1:8080
    // Port and IP are raw (no XOR)
    let data: [u8; 8] = [0x00, 0x01, 0x1F, 0x90, 10, 0, 0, 1];
    let addr = parse_mapped_address(&data).unwrap();
    assert_eq!(addr, "10.0.0.1:8080".parse::<SocketAddr>().unwrap());
}

#[test]
fn mapped_ipv6_basic() {
    // Target: fe80::1 port 8080
    let data: [u8; 20] = [
        0x00, 0x02, 0x1F, 0x90, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];
    let addr = parse_mapped_address(&data).unwrap();
    assert_eq!(addr, "[fe80::1]:8080".parse::<SocketAddr>().unwrap());
}

#[test]
fn mapped_too_short() {
    assert!(parse_mapped_address(&[0x00, 0x01]).is_none());
}

// -- STUN response parsing integration test --

#[test]
fn stun_response_xor_mapped_ipv4() {
    // Build a minimal valid STUN response with XOR-MAPPED-ADDRESS
    let mut resp = vec![0u8; 40];
    // STUN Binding Response: type=0x0101, length=12, magic, tid
    resp[0] = 0x01;
    resp[1] = 0x01;
    resp[2] = 0x00;
    resp[3] = 0x0C; // length = 12 (attr header 4 + value 8)
    resp[4] = 0x21;
    resp[5] = 0x12;
    resp[6] = 0xA4;
    resp[7] = 0x42;
    // tid = zeros (bytes 8..20)

    // XOR-MAPPED-ADDRESS attribute: type=0x0020, length=8
    resp[20] = 0x00;
    resp[21] = 0x20;
    resp[22] = 0x00;
    resp[23] = 0x08;
    // family=0x01, xport, xip for 192.168.1.1:8080
    resp[24] = 0x00;
    resp[25] = 0x01; // reserved + family IPv4
    resp[26] = 0x3E;
    resp[27] = 0x82; // xport
    resp[28] = 0xE1;
    resp[29] = 0xBA;
    resp[30] = 0xA5;
    resp[31] = 0x43; // xip

    // Parse attributes manually (simulating stun_bind_request logic)
    let n = 32;
    let mut pos = 20usize;
    let mut result = None;
    while pos + 4 <= n {
        let attr_type = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let attr_len = u16::from_be_bytes([resp[pos + 2], resp[pos + 3]]) as usize;
        pos += 4;
        if pos + attr_len > n {
            break;
        }
        if attr_type == 0x0020 {
            result = parse_xor_mapped_address(&resp[pos..pos + attr_len]);
            break;
        }
        pos += attr_len;
        pos = (pos + 3) & !3;
    }
    let addr = result.unwrap();
    assert_eq!(addr, "192.168.1.1:8080".parse::<SocketAddr>().unwrap());
}
