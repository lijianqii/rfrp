use serde::{Deserialize, Serialize};
use crate::config_info::base_info_ops::BaseInfoGetter;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum RunningMode {
    Server,
    Client,
    Unknown,
}

/// Connection type for a proxy.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ProxyConType {
    Tcp,
    P2p,
}

impl std::fmt::Display for ProxyConType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyConType::Tcp => write!(f, "tcp"),
            ProxyConType::P2p => write!(f, "p2p"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ControlInfo {
    pub command: String,
    pub args: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DataInfo {
    pub conn_id: u64,
    pub client: ClientInfo,
    pub data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConfigInfo {
    running_mode: RunningMode,
    server: ServerInfo,
    client_proxy: Vec<ClientInfo>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerInfo {
    server_ip: String,
    server_port: u16,
    auth_token: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClientInfo {
    name: String,
    bind_port: u16,
    proxy_ip: String,
    proxy_port: u16,
    proxy_con_type: ProxyConType,
    /// P2P mode: the name of the peer client to connect to.
    #[serde(default)]
    pub p2p_peer_name: Option<String>,
    /// P2P mode: STUN server address (e.g. "stun.l.google.com:19302").
    #[serde(default)]
    pub p2p_stun_server: Option<String>,
}

/// Server's response to a registration request.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegisterResponse {
    pub client: ClientInfo,
    pub success: bool,
}

// ========== P2P Signaling Types ==========

/// Types of P2P signaling messages exchanged through the server.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum P2pSignalType {
    /// Initiate a P2P connection, carries local UDP endpoint info.
    Offer,
    /// Respond to an Offer, carries own UDP endpoint info.
    Answer,
    /// NAT traversal candidate / additional address info.
    Candidate,
    /// Keep-alive ping.
    Ping,
    /// Keep-alive pong.
    Pong,
    /// Query whether a peer is online on this server.
    PeerQuery,
    /// Response to a PeerQuery: payload is JSON `{"found": true/false}`.
    PeerResponse,
}

/// A P2P signaling frame, relayed by the server between two peers.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct P2pSignalInfo {
    pub signal_type: P2pSignalType,
    pub from_client: String,
    pub to_client: String,
    /// Serialized payload (e.g. SocketAddr string, or JSON with address info).
    pub payload: Vec<u8>,
}

/// P2P direct data frame (used after hole punching, over UDP).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct P2pDataInfo {
    pub conn_id: u64,
    pub from_client: String,
    pub to_client: String,
    pub data: Vec<u8>,
}

impl ConfigInfo {
    pub fn get_running_mode(&self) -> &RunningMode {
        &self.running_mode
    }

    pub fn get_server(&self) -> &ServerInfo {
        &self.server
    }

    pub fn get_client_proxy(&self) -> &Vec<ClientInfo> {
        &self.client_proxy
    }
}

impl ClientInfo {
    pub fn get_bind_port(&self) -> u16 {
        self.bind_port
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn get_proxy_con_type(&self) -> &ProxyConType {
        &self.proxy_con_type
    }

    pub fn is_p2p(&self) -> bool {
        self.proxy_con_type == ProxyConType::P2p
    }

    pub fn get_p2p_peer_name(&self) -> Option<&str> {
        self.p2p_peer_name.as_deref()
    }

    pub fn get_p2p_stun_server(&self) -> Option<&str> {
        self.p2p_stun_server.as_deref()
    }

}

impl ServerInfo {
    pub fn get_auth_token(&self) -> &str {
        &self.auth_token
    }
}

impl BaseInfoGetter for ClientInfo {
    fn get_ip(&self) -> &str {
        &self.proxy_ip
    }

    fn get_port(&self) -> u16 {
        self.proxy_port
    }
}

impl BaseInfoGetter for ServerInfo {
    fn get_ip(&self) -> &str {
        &self.server_ip
    }

    fn get_port(&self) -> u16 {
        self.server_port
    }
}
