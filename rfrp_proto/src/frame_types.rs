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
