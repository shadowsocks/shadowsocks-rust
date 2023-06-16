use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(any(target_os = "linux"))] {
        mod linux;
        pub use self::linux::*;
    } else if #[cfg(target_vendor = "apple")] {
        mod apple;
        pub use self::apple::*;
    } else if #[cfg(any(target_os = "freebsd", target_os = "openbsd"))] {
        mod bsd;
        pub use self::bsd::*;
    } else if #[cfg(target_os = "android")] {
        mod android;
        pub use self::android::*;
    }
}
