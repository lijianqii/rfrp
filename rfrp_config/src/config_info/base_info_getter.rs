
pub trait BaseInfoGetter {
    fn get_ip(&self) -> &str;
    fn get_port(&self) -> u16;
    fn get_addr(&self) -> String {
        format!("{}:{}", self.get_ip(), self.get_port())
    }
}
