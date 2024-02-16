//! Logging facilities with log4rs

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

/// Initialize logger with provided configuration
#[allow(dead_code)]
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

    let (l1, l2) = match debug_level {
        0 => (LevelFilter::Info, LevelFilter::Off),
        1 => (LevelFilter::Debug, LevelFilter::Off),
        2 => (LevelFilter::Trace, LevelFilter::Off),
        3 => (LevelFilter::Trace, LevelFilter::Debug),
        _ => (LevelFilter::Off, LevelFilter::Trace),
    };

    let config = match debug_level {
        0..=3 => logging_builder
            .logger(Logger::builder().build(bin_name, l1))
            .logger(Logger::builder().build("shadowsocks_rust", l1))
            .logger(Logger::builder().build("shadowsocks", l1))
            .logger(Logger::builder().build("shadowsocks_service", l1)),
        _ => logging_builder,
    }
    .build(Root::builder().appender("console").build(l2))
    .expect("logging");

    log4rs::init_config(config).expect("logging");
}
