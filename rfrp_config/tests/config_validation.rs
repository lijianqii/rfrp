use rfrp_config::config_info::base_info_ops::BaseInfoGetter;
use rfrp_config::config_info::base_types::{ConfigInfo, RunningMode};

// ── Config parsing tests ────────────────────────────────────────────────────

fn valid_server_json() -> &'static str {
    r#"{
        "running_mode": "Server",
        "server": {
            "server_ip": "0.0.0.0",
            "server_port": 11000,
            "auth_token": "secret-token"
        },
        "client_proxy": []
    }"#
}

fn valid_client_json() -> &'static str {
    r#"{
        "running_mode": "Client",
        "server": {
            "server_ip": "127.0.0.1",
            "server_port": 11000,
            "auth_token": "secret-token"
        },
        "client_proxy": [
            {
                "name": "ssh",
                "bind_port": 22001,
                "proxy_ip": "192.168.1.1",
                "proxy_port": 22,
                "proxy_con_type": "tcp"
            }
        ]
    }"#
}

#[test]
fn parse_server_config() {
    let config: ConfigInfo = serde_json::from_str(valid_server_json()).unwrap();
    assert!(matches!(config.get_running_mode(), RunningMode::Server));
    assert_eq!(config.get_server().get_ip(), "0.0.0.0");
    assert_eq!(config.get_server().get_port(), 11000);
    assert_eq!(config.get_server().get_auth_token(), "secret-token");
    assert!(config.get_client_proxy().is_empty());
}

#[test]
fn parse_client_config() {
    let config: ConfigInfo = serde_json::from_str(valid_client_json()).unwrap();
    assert!(matches!(config.get_running_mode(), RunningMode::Client));
    assert_eq!(config.get_client_proxy().len(), 1);
    assert_eq!(config.get_client_proxy()[0].get_name(), "ssh");
    assert_eq!(config.get_client_proxy()[0].get_bind_port(), 22001);
    assert_eq!(config.get_client_proxy()[0].get_ip(), "192.168.1.1");
    assert_eq!(config.get_client_proxy()[0].get_port(), 22);
    assert_eq!(config.get_client_proxy()[0].get_proxy_con_type(), "tcp");
}

#[test]
fn parse_client_multiple_proxies() {
    let json = r#"{
        "running_mode": "Client",
        "server": {
            "server_ip": "127.0.0.1",
            "server_port": 11000,
            "auth_token": "token"
        },
        "client_proxy": [
            {
                "name": "ssh",
                "bind_port": 22001,
                "proxy_ip": "192.168.1.1",
                "proxy_port": 22,
                "proxy_con_type": "tcp"
            },
            {
                "name": "rdp",
                "bind_port": 33890,
                "proxy_ip": "192.168.1.2",
                "proxy_port": 3389,
                "proxy_con_type": "tcp"
            }
        ]
    }"#;
    let config: ConfigInfo = serde_json::from_str(json).unwrap();
    assert_eq!(config.get_client_proxy().len(), 2);
    assert_eq!(config.get_client_proxy()[0].get_name(), "ssh");
    assert_eq!(config.get_client_proxy()[1].get_name(), "rdp");
}

#[test]
fn parse_p2p_proxy_with_stun() {
    let json = r#"{
        "running_mode": "Client",
        "server": {
            "server_ip": "127.0.0.1",
            "server_port": 11000,
            "auth_token": "token"
        },
        "client_proxy": [
            {
                "name": "peer-a",
                "bind_port": 55003,
                "proxy_ip": "192.168.1.240",
                "proxy_port": 3389,
                "proxy_con_type": "p2p",
                "p2p_stun_server": "stun.l.google.com:19302"
            }
        ]
    }"#;
    let config: ConfigInfo = serde_json::from_str(json).unwrap();
    let proxy = &config.get_client_proxy()[0];
    assert_eq!(proxy.get_proxy_con_type(), "p2p");
    assert_eq!(
        proxy.get_p2p_stun_server(),
        Some("stun.l.google.com:19302")
    );
}

// ── Validation tests ────────────────────────────────────────────────────────

#[test]
fn validate_server_valid() {
    let config: ConfigInfo = serde_json::from_str(valid_server_json()).unwrap();
    assert!(config.validate().is_ok());
}

#[test]
fn validate_server_empty_ip() {
    let json = r#"{
        "running_mode": "Server",
        "server": {
            "server_ip": "",
            "server_port": 11000,
            "auth_token": "token"
        },
        "client_proxy": []
    }"#;
    let config: ConfigInfo = serde_json::from_str(json).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.contains("server_ip is empty"));
}

#[test]
fn validate_server_invalid_ip() {
    let json = r#"{
        "running_mode": "Server",
        "server": {
            "server_ip": "not-an-ip",
            "server_port": 11000,
            "auth_token": "token"
        },
        "client_proxy": []
    }"#;
    let config: ConfigInfo = serde_json::from_str(json).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.contains("not a valid IPv4/IPv6 address"));
}

#[test]
fn validate_server_zero_port() {
    let json = r#"{
        "running_mode": "Server",
        "server": {
            "server_ip": "0.0.0.0",
            "server_port": 0,
            "auth_token": "token"
        },
        "client_proxy": []
    }"#;
    let config: ConfigInfo = serde_json::from_str(json).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.contains("server_port 0 is invalid"));
}

#[test]
fn validate_server_empty_auth_token() {
    let json = r#"{
        "running_mode": "Server",
        "server": {
            "server_ip": "0.0.0.0",
            "server_port": 11000,
            "auth_token": ""
        },
        "client_proxy": []
    }"#;
    let config: ConfigInfo = serde_json::from_str(json).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.contains("auth_token is empty"));
}

#[test]
fn validate_client_valid() {
    let config: ConfigInfo = serde_json::from_str(valid_client_json()).unwrap();
    assert!(config.validate().is_ok());
}

#[test]
fn validate_client_empty_proxy_list() {
    let json = r#"{
        "running_mode": "Client",
        "server": {
            "server_ip": "127.0.0.1",
            "server_port": 11000,
            "auth_token": "token"
        },
        "client_proxy": []
    }"#;
    let config: ConfigInfo = serde_json::from_str(json).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.contains("client_proxy is empty"));
}

#[test]
fn validate_client_invalid_proxy_ip() {
    let json = r#"{
        "running_mode": "Client",
        "server": {
            "server_ip": "127.0.0.1",
            "server_port": 11000,
            "auth_token": "token"
        },
        "client_proxy": [
            {
                "name": "bad",
                "bind_port": 22001,
                "proxy_ip": "999.999.999.999",
                "proxy_port": 22,
                "proxy_con_type": "tcp"
            }
        ]
    }"#;
    let config: ConfigInfo = serde_json::from_str(json).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.contains("not a valid IPv4/IPv6 address"));
}

#[test]
fn validate_client_invalid_proxy_port() {
    let json = r#"{
        "running_mode": "Client",
        "server": {
            "server_ip": "127.0.0.1",
            "server_port": 11000,
            "auth_token": "token"
        },
        "client_proxy": [
            {
                "name": "bad",
                "bind_port": 22001,
                "proxy_ip": "192.168.1.1",
                "proxy_port": 0,
                "proxy_con_type": "tcp"
            }
        ]
    }"#;
    let config: ConfigInfo = serde_json::from_str(json).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.contains("proxy_port 0 is invalid"));
}

// ── Server address helper ───────────────────────────────────────────────────

#[test]
fn server_addr_format() {
    let config: ConfigInfo = serde_json::from_str(valid_server_json()).unwrap();
    assert_eq!(config.get_server().get_addr(), "0.0.0.0:11000");
}

#[test]
fn client_proxy_addr_format() {
    let config: ConfigInfo = serde_json::from_str(valid_client_json()).unwrap();
    assert_eq!(config.get_client_proxy()[0].get_addr(), "192.168.1.1:22");
}
