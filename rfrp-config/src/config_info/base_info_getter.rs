
pub trait BaseInfoGetter {
    fn get_ip(&self) -> &str;
    fn get_port(&self) -> u16;
}
