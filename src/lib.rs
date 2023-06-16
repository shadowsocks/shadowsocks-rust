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
pub mod vparser;

/// Exit code when server exits unexpectedly
pub const EXIT_CODE_SERVER_EXIT_UNEXPECTEDLY: sysexits::ExitCode = sysexits::ExitCode::Software;
/// Exit code when server aborted
pub const EXIT_CODE_SERVER_ABORTED: sysexits::ExitCode = sysexits::ExitCode::Software;
/// Exit code when loading configuration from file fails
pub const EXIT_CODE_LOAD_CONFIG_FAILURE: sysexits::ExitCode = sysexits::ExitCode::Config;
/// Exit code when loading ACL from file fails
pub const EXIT_CODE_LOAD_ACL_FAILURE: sysexits::ExitCode = sysexits::ExitCode::Config;
/// Exit code when insufficient params are passed via CLI
pub const EXIT_CODE_INSUFFICIENT_PARAMS: sysexits::ExitCode = sysexits::ExitCode::Usage;

/// Build timestamp in UTC
pub const BUILD_TIME: &str = build_time::build_time_utc!();

/// shadowsocks version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
