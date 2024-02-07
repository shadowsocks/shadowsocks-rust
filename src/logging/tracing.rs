//! Logging facilities with tracing

use std::collections::HashMap;
use std::path::Path;
use std::{collections::HashSet, fs::File};

use trace4rs::config::{Appender as ConfigAppender, AppenderId, Format, LevelFilter, Target};
use trace4rs::{config::Logger, Config, Handle};

use crate::config::LogConfig;

#[allow(dead_code)]
/// Initialize logger ([log4rs](https://crates.io/crates/log4rs)) from yaml configuration file
pub fn init_with_file<P>(path: P)
where
    P: AsRef<Path>,
{
    // log4rs uses YAML as configuration format.
    let mut fp = match File::open(path.as_ref()) {
        Ok(fp) => fp,
        Err(err) => {
            panic!("failed to open file {}, error: {}", path.as_ref().display(), err);
        }
    };

    let config: Config = match serde_yaml::from_reader(&mut fp) {
        Ok(c) => c,
        Err(err) => {
            panic!("failed to read file {}, error: {}", path.as_ref().display(), err);
        }
    };

    let handle = match Handle::try_from(&config) {
        Ok(h) => h,
        Err(err) => {
            panic!(
                "failed to initialize trace4rs Handle, config file: {}, error: {}",
                path.as_ref().display(),
                err
            );
        }
    };

    match tracing::subscriber::set_global_default(handle.subscriber()) {
        Ok(..) => {}
        Err(err) => {
            panic!(
                "failed to initialize tracing subscriber, config file: {}, error: {}",
                path.as_ref().display(),
                err
            );
        }
    }
}

/// Initialize logger with provided configuration
pub fn init_with_config(bin_name: &str, config: &LogConfig) {
    let debug_level = config.level;
    let without_time = config.format.without_time;

    let mut pattern = String::new();
    if !without_time {
        pattern += "{T} ";
    }
    pattern += "{l} [{t}] {m} {f}";

    let (l1, l2) = match debug_level {
        0 => (LevelFilter::INFO, LevelFilter::OFF),
        1 => (LevelFilter::DEBUG, LevelFilter::OFF),
        2 => (LevelFilter::TRACE, LevelFilter::OFF),
        3 => (LevelFilter::TRACE, LevelFilter::DEBUG),
        _ => (LevelFilter::OFF, LevelFilter::TRACE),
    };

    let default_logger = Logger {
        appenders: HashSet::from([AppenderId("console".to_owned())]),
        level: l2,
        format: Format::Custom(pattern.clone()),
    };

    let mut loggers = HashMap::new();
    if debug_level <= 3 {
        let l1_logger = Logger {
            appenders: HashSet::from([AppenderId("console".to_owned())]),
            level: l1,
            format: Format::Custom(pattern),
        };
        loggers.insert(Target(bin_name.to_owned()), l1_logger.clone());
        loggers.insert(Target("shadowsocks_rust".to_owned()), l1_logger.clone());
        loggers.insert(Target("shadowsocks".to_owned()), l1_logger.clone());
        loggers.insert(Target("shadowsocks_service".to_owned()), l1_logger);
    }

    let config = Config {
        default: default_logger,
        appenders: HashMap::from([(AppenderId("console".to_owned()), ConfigAppender::console())]),
        loggers,
    };

    let handle = match Handle::try_from(&config) {
        Ok(h) => h,
        Err(err) => {
            panic!("failed to initialize trace4rs Handle, error: {}", err);
        }
    };

    match tracing::subscriber::set_global_default(handle.subscriber()) {
        Ok(..) => {}
        Err(err) => {
            panic!("failed to initialize tracing subscriber, error: {}", err);
        }
    }
}
