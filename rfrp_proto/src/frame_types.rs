use rfrp_config::config_info::base_types::ClientInfo;
use rfrp_config::config_info::base_types::ControlInfo;
use rfrp_config::config_info::base_types::DataInfo;
use rfrp_config::config_info::base_types::RegisterResponse;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum RfrpFrame {
    Register(ClientInfo),
    RegisterAck(RegisterResponse),
    Control(ControlInfo),
    Data(DataInfo),
}

impl RfrpFrame {
    /// Create a Data frame. Uses the numeric `proxy_id` (assigned during
    /// registration) instead of the proxy name string to minimize per-frame
    /// wire overhead — a u32 is 4 bytes vs. a variable-length string.
    pub fn new_data_frame(data: Bytes, proxy_id: u32, conn_id: u64) -> Self {
        RfrpFrame::Data(DataInfo {
            conn_id,
            proxy_id,
            data,
        })
    }

    pub fn new_reg_ack_frame(client_info: &ClientInfo, success: bool, proxy_id: u32) -> Self {
        RfrpFrame::RegisterAck(RegisterResponse {
            client: client_info.clone(),
            success,
            proxy_id,
        })
    }

    /// Create a heartbeat ping frame. The client sends this periodically;
    /// the server must reply with a pong frame.
    pub fn new_ping_frame() -> Self {
        RfrpFrame::Control(ControlInfo {
            command: "ping".to_string(),
            args: Vec::new(),
        })
    }

    /// Create a heartbeat pong frame. Sent by the server in response to a ping.
    pub fn new_pong_frame() -> Self {
        RfrpFrame::Control(ControlInfo {
            command: "pong".to_string(),
            args: Vec::new(),
        })
    }

    /// Returns true if this Control frame carries a "ping" heartbeat.
    pub fn is_ping(&self) -> bool {
        matches!(self, RfrpFrame::Control(c) if c.command == "ping")
    }

    /// Returns true if this Control frame carries a "pong" heartbeat.
    pub fn is_pong(&self) -> bool {
        matches!(self, RfrpFrame::Control(c) if c.command == "pong")
    }
}
