//! Logging facilities

use std::path::Path;

use crate::config::LogConfig;

mod log4rs;
mod tracing;

/// Initialize logger ([log4rs](https://crates.io/crates/log4rs), [trace4rs](https://crates.io/crates/trace4rs)) from yaml configuration file
pub fn init_with_file<P>(path: P)
where
    P: AsRef<Path>,
{
    log4rs::init_with_file(path);
    // FIXME: 2024-02-04 Temporary disable.
    // trace4rs configuration file doesn't share exactly the same value with log4rs.
    //
    // tracing::init_with_file(path);
}

/// Initialize logger with provided configuration
pub fn init_with_config(bin_name: &str, config: &LogConfig) {
    log4rs::init_with_config(bin_name, config);
    tracing::init_with_config(bin_name, config);
}

/// Init a default logger
pub fn init_with_default(bin_name: &str) {
    init_with_config(bin_name, &LogConfig::default());
}
