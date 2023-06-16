use std::{env::current_dir, path::Path};

use daemonize::Daemonize;
use log::error;

/// Daemonize a server process in a *nix standard way
///
/// This function will redirect `stdout`, `stderr` to `/dev/null`,
/// and follow the exact behavior in shadowsocks-libev
pub fn daemonize<F: AsRef<Path>>(pid_path: Option<F>) {
    let pwd = current_dir()
        .unwrap_or_else(|err| panic!("cannot get current working directory, {err:?}"))
        .canonicalize()
        .unwrap_or_else(|err| panic!("cannot get absolute path to working directory, {err:?}"));
    let mut d = Daemonize::new().umask(0).working_directory(pwd);

    if let Some(p) = pid_path {
        d = d.pid_file(p);
    }

    if let Err(err) = d.start() {
        error!("failed to daemonize, {:?} ({})", err, err);
    }
}
