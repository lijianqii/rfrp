use chrono::Local;
use std::io::Write;

pub fn init_logging() {
    env_logger::Builder::new()
        .filter(None, log::LevelFilter::Trace)
        .write_style(env_logger::WriteStyle::Always)
        .format(|buf, record| {
            writeln!(
                buf,
                "{} | {:>6} | {}:{:<4} | {} | - {}",
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
