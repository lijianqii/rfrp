use rfrp_config::config_info::base_types::ClientInfo;
use rfrp_config::config_info::base_types::ControlInfo;
use rfrp_config::config_info::base_types::DataInfo;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum RfrpFrame {
    Register(ClientInfo),
    Control(ControlInfo),
    Data(DataInfo),
}

impl RfrpFrame {
    pub fn new_data_frame(data: &[u8], client_info: &ClientInfo) -> Self {
        RfrpFrame::Data(DataInfo {
            data: data.to_vec(),
            client: client_info.clone(),
        })
    }

    pub fn new_reg_frame(client_info: &ClientInfo) -> Self {
        RfrpFrame::Register(client_info.clone())
    }
}
