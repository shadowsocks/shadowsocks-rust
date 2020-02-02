use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(any(target_os = "linux", target_os = "android"))] {
        mod linux;
        pub use self::linux::*;
    } else if #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "netbsd", target_os = "openbsd", target_os = "dragonfly"))] {
        mod bsd;
        pub use self::bsd::*;
    }
}
