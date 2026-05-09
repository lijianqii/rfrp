use crate::frame_types::RfrpFrame;

impl RfrpFrame {
    /// 将 JSON 字节流解析为 RfrpFrame 协议帧
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let json = std::str::from_utf8(bytes)
            .map_err(|e| format!("Invalid UTF-8: {}", e))?;
        serde_json::from_str(json)
            .map_err(|e| format!("Failed to decode frame: {}", e))
    }
}
