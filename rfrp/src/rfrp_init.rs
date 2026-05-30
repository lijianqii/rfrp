use chrono::Local;
use std::io::Write;

pub fn init_logging() {
    let log_level = std::env::var("RFRP_LOG")
        .ok()
        .and_then(|s| match s.to_lowercase().as_str() {
            "trace" => Some(log::LevelFilter::Trace),
            "debug" => Some(log::LevelFilter::Debug),
            "info" => Some(log::LevelFilter::Info),
            "warn" => Some(log::LevelFilter::Warn),
            "error" => Some(log::LevelFilter::Error),
            _ => None,
        })
        .unwrap_or(log::LevelFilter::Info);

    env_logger::Builder::new()
        .filter(None, log_level)
        .write_style(env_logger::WriteStyle::Always)
        .format(|buf, record| {
            writeln!(
                buf,
                "{} | {:>6} | {:<}:{:<4} | {} | - {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                record.file().unwrap_or(""),
                record.line().unwrap_or(0),
                record.module_path().unwrap_or(""),
                record.args()
            )
        })
        .init();
}
