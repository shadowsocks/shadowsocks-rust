//! Shadowsocks service command line utilities

pub mod allocator;
#[cfg(unix)]
pub mod daemonize;
#[cfg(feature = "logging")]
pub mod logging;
pub mod monitor;
pub mod validator;

pub const EXIT_CODE_SERVER_EXIT_UNEXPECTEDLY: i32 = exitcode::SOFTWARE;
pub const EXIT_CODE_SERVER_ABORTED: i32 = exitcode::SOFTWARE;
pub const EXIT_CODE_LOAD_CONFIG_FAILURE: i32 = exitcode::CONFIG;
pub const EXIT_CODE_LOAD_ACL_FAILURE: i32 = exitcode::CONFIG;

#[allow(dead_code)]
pub const BUILD_TIME: &str = build_time::build_time_utc!();
