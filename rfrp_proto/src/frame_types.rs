use rfrp_config::config_info::base_types::ClientInfo;
use rfrp_config::config_info::base_types::ControlInfo;
use rfrp_config::config_info::base_types::DataInfo;
use rfrp_config::config_info::base_types::P2pDataInfo;
use rfrp_config::config_info::base_types::P2pSignalInfo;
use rfrp_config::config_info::base_types::P2pSignalType;
use rfrp_config::config_info::base_types::RegisterResponse;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum RfrpFrame {
    Register(ClientInfo),
    RegisterAck(RegisterResponse),
    Control(ControlInfo),
    Data(DataInfo),
    /// P2P signaling frame: relayed by server between peers for NAT traversal.
    P2pSignal(P2pSignalInfo),
    /// P2P direct data frame: sent over UDX after hole punching.
    P2pData(P2pDataInfo),
}

impl RfrpFrame {
    /// Create a Data frame. Uses `proxy_name` instead of the full `ClientInfo`
    /// to avoid redundant serialization of unchanging data every frame.
    pub fn new_data_frame(data: Bytes, proxy_name: &str, conn_id: u64) -> Self {
        RfrpFrame::Data(DataInfo {
            conn_id,
            proxy_name: proxy_name.to_string(),
            data,
        })
    }

    pub fn new_reg_ack_frame(client_info: &ClientInfo, success: bool) -> Self {
        RfrpFrame::RegisterAck(RegisterResponse {
            client: client_info.clone(),
            success,
        })
    }

    pub fn new_p2p_signal(
        signal_type: P2pSignalType,
        from_client: &str,
        to_client: &str,
        payload: Vec<u8>,
    ) -> Self {
        RfrpFrame::P2pSignal(P2pSignalInfo {
            signal_type,
            from_client: from_client.to_string(),
            to_client: to_client.to_string(),
            payload,
        })
    }
}
