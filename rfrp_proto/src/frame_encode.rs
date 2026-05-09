use crate::frame_types::RfrpFrame;

impl RfrpFrame {
    /// 将 RfrpFrame 序列化为 JSON 字节流
    pub fn encode(object: &RfrpFrame) -> Vec<u8> {
        serde_json::to_vec(object).expect("Failed to encode RfrpFrame")
    }
}
