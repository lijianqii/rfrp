use rfrp_config::config_info::base_types::ClientInfo;
use rfrp_config::config_info::base_types::ControlInfo;
use rfrp_config::config_info::base_types::DataInfo;
use rfrp_config::config_info::base_types::RegisterResponse;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum RfrpFrame {
    Register(ClientInfo),
    RegisterAck(RegisterResponse),
    Control(ControlInfo),
    Data(DataInfo),
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
}
