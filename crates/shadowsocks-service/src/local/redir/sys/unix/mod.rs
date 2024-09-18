use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(any(target_os = "macos",
                 target_os = "ios",
                 target_os = "freebsd"))] {
        pub mod bsd_pf;
    }
}

cfg_if! {
    if #[cfg(any(target_os = "macos",
                 target_os = "ios"))] {
        #[path = "pfvar_bindgen_macos.rs"]
        #[allow(dead_code, non_upper_case_globals, non_snake_case, non_camel_case_types)]
        #[allow(clippy::useless_transmute, clippy::too_many_arguments, clippy::unnecessary_cast)]
        mod pfvar;
    } else if #[cfg(target_os = "freebsd")] {
        #[path = "pfvar_bindgen_freebsd.rs"]
        #[allow(dead_code, non_upper_case_globals, non_snake_case, non_camel_case_types)]
        #[allow(clippy::useless_transmute, clippy::too_many_arguments, clippy::unnecessary_cast)]
        mod pfvar;
    } else if #[cfg(target_os = "openbsd")] {
        #[path = "pfvar_bindgen_openbsd.rs"]
        #[allow(dead_code, non_upper_case_globals, non_snake_case, non_camel_case_types)]
        #[allow(clippy::useless_transmute, clippy::too_many_arguments, clippy::unnecessary_cast)]
        mod pfvar;
    }
}
