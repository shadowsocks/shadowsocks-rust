//! Logging facilities

use std::path::Path;

use log::warn;

use crate::config::LogConfig;

mod log4rs;
mod tracing;

/// Initialize logger ([log4rs](https://crates.io/crates/log4rs), [trace4rs](https://crates.io/crates/trace4rs)) from yaml configuration file
pub fn init_with_file<P>(path: P)
where
    P: AsRef<Path>,
{
    log4rs::init_with_file(path);

    warn!(
        "log4rs doesn't support the tracing (https://crates.io/crates/tracing) framework, 
         so it would be removed in the future. Consider configure logging with RUST_LOG environment variable. 
         Check more configuration detail in https://docs.rs/tracing-subscriber/latest/tracing_subscriber/fmt/index.html#filtering-events-with-environment-variables ."
    );
}

/// Initialize logger with provided configuration
pub fn init_with_config(bin_name: &str, config: &LogConfig) {
    // log4rs::init_with_config(bin_name, config);
    tracing::init_with_config(bin_name, config);
}

/// Init a default logger
pub fn init_with_default(bin_name: &str) {
    init_with_config(bin_name, &LogConfig::default());
}
