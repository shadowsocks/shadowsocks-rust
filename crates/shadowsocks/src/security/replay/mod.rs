use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "security-replay-attack-detect")] {
        mod ppbloom;
        pub use self::ppbloom::*;
    } else {
        mod dummy;
        pub use self::dummy::*;
    }
}
