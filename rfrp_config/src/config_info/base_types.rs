use crate::config_info::base_info_ops::BaseInfoGetter;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum RunningMode {
    Server,
    Client,
    Unknown,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ControlInfo {
    pub command: String,
    pub args: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DataInfo {
    pub conn_id: u64,
    /// Proxy name — used to look up routing on the server side
    /// and client config on the client side. Avoids carrying the full
    /// ClientInfo (which never changes) in every data frame.
    pub proxy_name: String,
    pub data: Bytes,
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
    proxy_con_type: String,
    #[serde(default)]
    p2p_stun_server: Option<String>,
}

/// Server's response to a registration request.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegisterResponse {
    pub client: ClientInfo,
    pub success: bool,
}

/// P2P signaling message type.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum P2pSignalType {
    PeerQuery,
    PeerFound,
    Offer,
    Answer,
    Candidate,
    Ping,
    Pong,
}

/// P2P signaling frame payload.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct P2pSignalInfo {
    pub signal_type: P2pSignalType,
    pub from_client: String,
    pub to_client: String,
    pub payload: Vec<u8>,
}

/// P2P direct data frame (sent over UDX, not through server).
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

    pub fn get_client_proxy(&self) -> &[ClientInfo] {
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

    pub fn get_proxy_con_type(&self) -> &str {
        &self.proxy_con_type
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
