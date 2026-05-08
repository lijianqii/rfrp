use serde::{Deserialize, Serialize};
use crate::config_info::base_info_getter::BaseInfoGetter;

#[derive(Serialize, Deserialize, Debug)]
pub enum RunningMode {
    Server,
    Client,
    Unknown,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ConfigInfo {
    pub running_mode: RunningMode,
    pub server: ServerInfo,
    pub client_proxy: Vec<ClientInfo>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ServerInfo {
    server_ip: String,
    server_port: u16,
    auth_token: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ClientInfo {
    name: String,
    bind_port: u16,
    proxy_ip: String,
    proxy_port: u16,
    proxy_con_type: String,
}

impl ClientInfo {
    pub fn get_bind_port(&self) -> u16 {
        self.bind_port
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
