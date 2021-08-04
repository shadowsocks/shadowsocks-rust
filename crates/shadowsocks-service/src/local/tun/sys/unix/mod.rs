use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(any(target_os = "linux", target_os = "android"))] {
        mod linux;
        pub use self::linux::*;
    } else if #[cfg(target_vendor = "apple")] {
        mod macos;
        pub use self::macos::*;
    } else if #[cfg(any(target_os = "freebsd", target_os = "openbsd"))] {
        mod bsd;
        pub use self::bsd::*;
    }
}
