//! Shadowsocks service command line utilities

pub mod allocator;
pub mod config;
#[cfg(unix)]
pub mod daemonize;
pub mod error;
#[cfg(feature = "logging")]
pub mod logging;
pub mod monitor;
pub mod password;
pub mod service;
pub mod sys;
pub mod vparser;

/// Build timestamp in UTC
pub const BUILD_TIME: &str = build_time::build_time_utc!();

/// shadowsocks version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
