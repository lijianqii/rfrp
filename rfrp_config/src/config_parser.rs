use super::config_info::base_types::ConfigInfo;
use super::config_info::base_types::RunningMode;
use super::config_info::base_info_getter::BaseInfoGetter;
use log::{debug, warn};
use std::net::{Ipv4Addr, Ipv6Addr};

impl ConfigInfo {
    pub fn new(config_path: &str) -> Self {
        let content = match std::fs::read_to_string(config_path) {
            Ok(content) => content,
            Err(e) => panic!("Failed to read config file: {}", e),
        };

        debug!("Parsing config file: {}, read content: {:?}", config_path, content);

        let configs: ConfigInfo = match serde_json::from_str(&content) {
            Ok(config) => config,
            Err(e) => panic!("Failed to parse config file: {}", e),
        };

        match configs.get_running_mode() {
            RunningMode::Unknown => panic!("Running mode is unknown"),
            _ => {
                configs
            }
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        match self.get_running_mode() {
            RunningMode::Server => {
                self.validate_server()?;
            }
            RunningMode::Client => {
                self.validate_clients()?;
            }
            RunningMode::Unknown => {
                return Err("running_mode is Unknown".to_string());
            }
        }
        Ok(())
    }

    fn validate_server(&self) -> Result<(), String> {
        let server = self.get_server();
        let ip = server.get_ip();
        let port = server.get_port();

        if ip.is_empty() {
            return Err("server.server_ip is empty".to_string());
        }
        if !Self::is_valid_ip(ip) {
            return Err(format!("server.server_ip '{}' is not a valid IPv4/IPv6 address", ip));
        }
        if !Self::is_valid_port(port) {
            return Err(format!("server.server_port {} is invalid (must be 1-65535)", port));
        }
        if server.get_auth_token().is_empty() {
            return Err("server.auth_token is empty".to_string());
        }

        debug!("Server validation passed: {}:{}", ip, port);
        Ok(())
    }

    fn validate_clients(&self) -> Result<(), String> {
        let clients = self.get_client_proxy();

        if clients.is_empty() {
            return Err(
                "client_proxy is empty, Client mode requires at least 1 usable entry".to_string(),
            );
        }

        let mut valid_count: usize = 0;
        let mut errors: Vec<String> = Vec::new();

        for (i, client) in clients.iter().enumerate() {
            let ip = client.get_ip();
            let port = client.get_port();

            if ip.is_empty() {
                errors.push(format!("client_proxy[{}]: proxy_ip is empty", i));
                continue;
            }
            if !Self::is_valid_ip(ip) {
                errors.push(format!(
                    "client_proxy[{}]: proxy_ip '{}' is not a valid IPv4/IPv6 address",
                    i, ip
                ));
                continue;
            }
            if !Self::is_valid_port(port) {
                errors.push(format!(
                    "client_proxy[{}]: proxy_port {} is invalid (must be 1-65535)",
                    i, port
                ));
                continue;
            }

            valid_count += 1;
            debug!("client_proxy[{}] '{}' validation passed: {}:{}", i, client.get_name(), ip, port);
        }

        if valid_count == 0 {
            return Err(format!(
                "No usable client_proxy entries found. Errors: [{}]",
                errors.join("; ")
            ));
        }

        debug!(
            "Client validation passed: {}/{} entries usable",
            valid_count,
            clients.len()
        );
        Ok(())
    }

    fn is_valid_ip(ip: &str) -> bool {
        ip.parse::<Ipv4Addr>().is_ok() || ip.parse::<Ipv6Addr>().is_ok()
    }

    fn is_valid_port(port: u16) -> bool {
        if port > 0 && port < 1024 {
            warn!(
                "port {} is in the privileged range (1-1023), root/admin permission may be required",
                port
            );
        }
        port > 0
    }

    pub fn debug_info(&self) {
        debug!("=== ConfigInfo ===");
        debug!("running_mode: {:?}", self.get_running_mode());
        debug!("--- ServerInfo ---");
        debug!("  server_ip:    {}", self.get_server().get_ip());
        debug!("  server_port:  {}", self.get_server().get_port());
        debug!("  server_addr:  {}", self.get_server().get_addr());
        debug!("  auth_token:   {}", self.get_server().get_auth_token());
        debug!("--- ClientProxy ({} entries) ---", self.get_client_proxy().len());
        for (i, client) in self.get_client_proxy().iter().enumerate() {
            debug!("  [{}] name:        {}", i, client.get_name());
            debug!("      bind_port:    {}", client.get_bind_port());
            debug!("      proxy_ip:     {}", client.get_ip());
            debug!("      proxy_port:   {}", client.get_port());
            debug!("      proxy_addr:   {}", client.get_addr());
            debug!("      proxy_con_type: {}", client.get_proxy_con_type());
        }
    }
}
