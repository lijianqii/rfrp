use crate::frame_types::RfrpFrame;

impl RfrpFrame {
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let json = std::str::from_utf8(bytes)
            .map_err(|e| format!("Invalid UTF-8: {}", e))?;
        serde_json::from_str(json)
            .map_err(|e| format!("Failed to decode frame: {}", e))
    }
}
