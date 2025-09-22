//! Daemonize server process

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(unix)] {
        mod unix;
        #[allow(unsafe_op_in_unsafe_fn, unused)]
        #[allow(clippy::module_inception)]
        mod daemonize;
        pub use self::unix::daemonize;
    } else {
        compile_error!("Process daemonization is not supported by the current platform");
    }
}
