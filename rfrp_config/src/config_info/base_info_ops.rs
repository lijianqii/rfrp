pub trait BaseInfoGetter {
    fn get_ip(&self) -> &str;
    fn get_port(&self) -> u16;
    /// Returns the cached "ip:port" string. Implementors should compute
    /// this once at construction time and store it.
    fn get_addr(&self) -> &str;
}
