use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(any(target_os = "linux", target_os = "android"))] {
        mod linux;
        pub use self::linux::*;
    } else if #[cfg(target_os = "macos")] {
        mod macos;
        pub use self::macos::*;
    } else if #[cfg(target_os = "freebsd")] {
        mod freebsd;
        pub use self::freebsd::*;
    } else {
        mod not_supported;
        pub use self::not_supported::*;
    }
}
