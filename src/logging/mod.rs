//! Logging facilities

use std::path::Path;

use log::LevelFilter;
use log4rs::{
    append::console::{ConsoleAppender, Target},
    config::{Appender, Config, Logger, Root},
    encode::pattern::PatternEncoder,
};

use crate::config::LogConfig;

/// Initialize logger ([log4rs](https://crates.io/crates/log4rs)) from yaml configuration file
pub fn init_with_file<P>(path: P)
where
    P: AsRef<Path>,
{
    log4rs::init_file(path, Default::default()).expect("init logging with file");
}

/// Initialize logger with default configuration
pub fn init_with_config(bin_name: &str, config: &LogConfig) {
    let debug_level = config.level;
    let without_time = config.format.without_time;

    let mut pattern = String::new();
    if !without_time {
        pattern += "{d} ";
    }
    pattern += "{h({l}):<5} ";
    if debug_level >= 1 {
        pattern += "[{P}:{I}] [{M}] ";
    }
    pattern += "{m}{n}";

    let logging_builder = Config::builder().appender(
        Appender::builder().build(
            "console",
            Box::new(
                ConsoleAppender::builder()
                    .encoder(Box::new(PatternEncoder::new(&pattern)))
                    .target(Target::Stderr)
                    .build(),
            ),
        ),
    );

    let config = match debug_level {
        0 => logging_builder
            .logger(Logger::builder().build(bin_name, LevelFilter::Info))
            .logger(Logger::builder().build("shadowsocks_rust", LevelFilter::Info))
            .logger(Logger::builder().build("shadowsocks", LevelFilter::Info))
            .logger(Logger::builder().build("shadowsocks_service", LevelFilter::Info))
            .build(Root::builder().appender("console").build(LevelFilter::Off)),
        1 => logging_builder
            .logger(Logger::builder().build(bin_name, LevelFilter::Debug))
            .logger(Logger::builder().build("shadowsocks_rust", LevelFilter::Debug))
            .logger(Logger::builder().build("shadowsocks", LevelFilter::Debug))
            .logger(Logger::builder().build("shadowsocks_service", LevelFilter::Debug))
            .build(Root::builder().appender("console").build(LevelFilter::Off)),
        2 => logging_builder
            .logger(Logger::builder().build(bin_name, LevelFilter::Trace))
            .logger(Logger::builder().build("shadowsocks_rust", LevelFilter::Trace))
            .logger(Logger::builder().build("shadowsocks", LevelFilter::Trace))
            .logger(Logger::builder().build("shadowsocks_service", LevelFilter::Trace))
            .build(Root::builder().appender("console").build(LevelFilter::Off)),
        3 => logging_builder
            .logger(Logger::builder().build(bin_name, LevelFilter::Trace))
            .logger(Logger::builder().build("shadowsocks_rust", LevelFilter::Trace))
            .logger(Logger::builder().build("shadowsocks", LevelFilter::Trace))
            .logger(Logger::builder().build("shadowsocks_service", LevelFilter::Trace))
            .build(Root::builder().appender("console").build(LevelFilter::Debug)),
        _ => logging_builder.build(Root::builder().appender("console").build(LevelFilter::Trace)),
    }
    .expect("logging");

    log4rs::init_config(config).expect("logging");
}

/// Init a default logger
pub fn init_with_default(bin_name: &str) {
    init_with_config(bin_name, &LogConfig::default());
}
