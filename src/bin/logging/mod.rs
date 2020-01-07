use std::env;

use env_logger::Builder;
use log::LevelFilter;

pub fn init(debug_level: u64, bin_name: &str) {
    let mut log_builder = Builder::new();
    log_builder.filter(None, LevelFilter::Info).default_format();

    match debug_level {
        0 => {
            // Default filter
        }
        1 => {
            log_builder.filter(Some(bin_name), LevelFilter::Debug);
        }
        2 => {
            log_builder
                .filter(Some(bin_name), LevelFilter::Debug)
                .filter(Some("shadowsocks"), LevelFilter::Debug);
        }
        3 => {
            log_builder
                .filter(Some(bin_name), LevelFilter::Trace)
                .filter(Some("shadowsocks"), LevelFilter::Trace);
        }
        _ => {
            log_builder.filter(None, LevelFilter::Trace);
        }
    }

    if let Ok(env_conf) = env::var("RUST_LOG") {
        log_builder.parse_filters(&env_conf);
    }

    log_builder.init();
}
