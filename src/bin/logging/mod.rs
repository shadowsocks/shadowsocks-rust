use std::io::Write;

use chrono::{offset::Local, SecondsFormat};
use env_logger::Builder;
use log::LevelFilter;

pub fn init(debug_level: u64, bin_name: &str) {
    let mut log_builder = Builder::from_default_env();
    log_builder.filter(Some(bin_name), LevelFilter::Info);
    log_builder.filter(Some("shadowsocks"), LevelFilter::Info);

    log_builder.format(move |buf, record| {
        write!(
            buf,
            "{} {:<5}",
            Local::now().to_rfc3339_opts(SecondsFormat::Millis, false),
            buf.default_styled_level(record.level())
        )?;

        if debug_level > 0 {
            if let Some(mp) = record.module_path() {
                write!(buf, " [{}]", mp)?;
            }
        }

        writeln!(buf, " {}", record.args())
    });

    match debug_level {
        0 => {
            // Default filter
        }
        1 => {
            log_builder
                .filter(Some(bin_name), LevelFilter::Debug)
                .filter(Some("shadowsocks"), LevelFilter::Debug);
        }
        2 => {
            log_builder
                .filter(Some(bin_name), LevelFilter::Trace)
                .filter(Some("shadowsocks"), LevelFilter::Trace);
        }
        3 => {
            log_builder
                .filter(Some(bin_name), LevelFilter::Trace)
                .filter(Some("shadowsocks"), LevelFilter::Trace)
                .filter(None, LevelFilter::Debug);
        }
        _ => {
            log_builder.filter(None, LevelFilter::Trace);
        }
    }

    log_builder.init();
}
