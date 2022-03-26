//! Shadowsocks service command line utilities

pub mod allocator;
pub mod config;
#[cfg(unix)]
pub mod daemonize;
#[cfg(feature = "logging")]
pub mod logging;
pub mod monitor;
pub mod password;
pub mod service;
pub mod sys;
pub mod validator;

/// Exit code when server exits unexpectly
pub const EXIT_CODE_SERVER_EXIT_UNEXPECTEDLY: i32 = exitcode::SOFTWARE;
/// Exit code when server aborted
pub const EXIT_CODE_SERVER_ABORTED: i32 = exitcode::SOFTWARE;
/// Exit code when loading configuration from file fails
pub const EXIT_CODE_LOAD_CONFIG_FAILURE: i32 = exitcode::CONFIG;
/// Exit code when loading ACL from file fails
pub const EXIT_CODE_LOAD_ACL_FAILURE: i32 = exitcode::CONFIG;

/// Build timestamp in UTC
pub const BUILD_TIME: &str = build_time::build_time_utc!();

/// shadowsocks version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
