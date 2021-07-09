//! Shadowsocks service command line utilities

pub mod allocator;
#[cfg(unix)]
pub mod daemonize;
#[cfg(feature = "logging")]
pub mod logging;
pub mod monitor;
pub mod validator;

pub const EXIT_CODE_SERVER_EXIT_UNEXPECTLY: i32 = 1;
pub const EXIT_CODE_SERVER_ABORTED: i32 = 2;
pub const EXIT_CODE_LOAD_CONFIG_FAILURE: i32 = 6;
pub const EXIT_CODE_LOAD_ACL_FAILURE: i32 = 7;
