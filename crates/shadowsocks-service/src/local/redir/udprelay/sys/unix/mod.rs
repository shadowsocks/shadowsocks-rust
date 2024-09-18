use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(any(target_os = "linux", target_os = "android"))] {
        mod linux;
        pub use self::linux::*;
    } else if #[cfg(target_os = "macos")] {
        mod macos;
        pub use self::macos::*;
    } else if #[cfg(any(target_os = "freebsd"))] {
        mod freebsd;
        pub use self::freebsd::*;
    } else if #[cfg(target_os = "openbsd")] {
        mod openbsd;
        pub use self::openbsd::*;
    } else {
        mod not_supported;
        pub use self::not_supported::*;
    }
}
