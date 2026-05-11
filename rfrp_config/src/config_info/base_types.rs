use serde::{Deserialize, Serialize};
use crate::config_info::base_info_ops::BaseInfoGetter;

#[derive(Serialize, Deserialize, Debug)]
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
    pub client: ClientInfo,
    pub data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ConfigInfo {
    running_mode: RunningMode,
    server: ServerInfo,
    client_proxy: Vec<ClientInfo>,
}

#[derive(Serialize, Deserialize, Debug)]
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
}

impl ConfigInfo {
    pub fn get_clients(&self) -> &Vec<ClientInfo> {
        &self.client_proxy
    }
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
}

impl BaseInfoGetter for ServerInfo {
    fn get_ip(&self) -> &str {
        &self.server_ip
    }

    fn get_port(&self) -> u16 {
        self.server_port
    }
}
