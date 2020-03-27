fn main() {
    // Enable redir (transparent proxy) for these targets
    if cfg!(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd"
    )) {
        println!("cargo:rustc-cfg=feature=\"local-redir\"")
    }
}
