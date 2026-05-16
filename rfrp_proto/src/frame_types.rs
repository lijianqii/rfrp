use rfrp_config::config_info::base_types::ClientInfo;
use rfrp_config::config_info::base_types::ControlInfo;
use rfrp_config::config_info::base_types::DataInfo;
use rfrp_config::config_info::base_types::P2pDataInfo;
use rfrp_config::config_info::base_types::P2pSignalInfo;
use rfrp_config::config_info::base_types::RegisterResponse;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum RfrpFrame {
    Register(ClientInfo),
    RegisterAck(RegisterResponse),
    Control(ControlInfo),
    Data(DataInfo),
    /// P2P signaling frame: relayed by server between peers for NAT traversal.
    P2pSignal(P2pSignalInfo),
    /// P2P direct data frame: sent over UDP after hole punching.
    P2pData(P2pDataInfo),
}

impl RfrpFrame {
    pub fn new_data_frame(data: &[u8], client_info: &ClientInfo, conn_id: u64) -> Self {
        RfrpFrame::Data(DataInfo {
            conn_id,
            data: data.to_vec(),
            client: client_info.clone(),
        })
    }

    pub fn new_reg_ack_frame(client_info: &ClientInfo, success: bool) -> Self {
        RfrpFrame::RegisterAck(RegisterResponse {
            client: client_info.clone(),
            success,
        })
    }

    /// Create a new P2P signaling frame.
    pub fn new_p2p_signal(
        signal_type: rfrp_config::config_info::base_types::P2pSignalType,
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

    /// Create a new P2P data frame.
    pub fn new_p2p_data_frame(
        data: &[u8],
        from_client: &str,
        to_client: &str,
        conn_id: u64,
    ) -> Self {
        RfrpFrame::P2pData(P2pDataInfo {
            conn_id,
            from_client: from_client.to_string(),
            to_client: to_client.to_string(),
            data: data.to_vec(),
        })
    }
}
