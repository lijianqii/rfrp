use crate::config_info::base_info_ops::BaseInfoGetter;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

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
    /// and client config on the client side. Uses `Arc<str>` so that
    /// cloning per frame is a cheap reference count bump instead of
    /// a heap allocation. Serialized as a plain string on the wire.
    pub proxy_name: Arc<str>,
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
    /// Cached "ip:port" string, computed once at construction time.
    #[serde(skip, default)]
    addr: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClientInfo {
    name: String,
    bind_port: u16,
    proxy_ip: String,
    proxy_port: u16,
    proxy_con_type: String,
    /// Cached "ip:port" string, computed once at construction time.
    #[serde(skip, default)]
    addr: String,
}

/// Server's response to a registration request.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegisterResponse {
    pub client: ClientInfo,
    pub success: bool,
}

impl ConfigInfo {
    /// Finish initialization after deserialization: cache computed fields.
    /// Call this once after `serde_json::from_str` or `ConfigInfo::new`.
    pub fn init(mut self) -> Self {
        self.server.addr = format!("{}:{}", self.server.server_ip, self.server.server_port);
        for client in &mut self.client_proxy {
            client.addr = format!("{}:{}", client.proxy_ip, client.proxy_port);
        }
        self
    }

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

    fn get_addr(&self) -> &str {
        &self.addr
    }
}

impl BaseInfoGetter for ServerInfo {
    fn get_ip(&self) -> &str {
        &self.server_ip
    }

    fn get_port(&self) -> u16 {
        self.server_port
    }

    fn get_addr(&self) -> &str {
        &self.addr
    }
}
