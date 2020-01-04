//! TCP Fast Open wrapper types

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "tfo")] {

        cfg_if! {
            if #[cfg(windows)] {
                #[path = "windows.rs"]
                mod sys;
            } else if #[cfg(any(target_os = "linux", target_os = "android"))] {
                #[path = "linux.rs"]
                mod sys;
            } else if #[cfg(any(target_os = "macos", target_os = "ios"))] {
                #[path = "macos.rs"]
                mod sys;
            } else if #[cfg(any(target_os = "freebsd", target_os = "fuchsia"))] {
                #[path = "bsd.rs"]
                mod sys;
            } else {
                compile_error!("TFO is not supported on this platform yet");
            }
        }

    } else {
        #[path = "non_tfo.rs"]
        mod sys;
    }
}

pub use sys::{bind_listener, connect_stream};
