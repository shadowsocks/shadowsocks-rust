use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(unix)] {
        mod unix;
        #[allow(unused_imports)]
        pub use self::unix::*;
    }

}
