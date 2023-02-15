//! This is a binary running in the local environment
//!
//! You have to provide all needed configuration attributes via command line parameters,
//! or you could specify a configuration file. The format of configuration file is defined
//! in mod `config`.

use std::{path::Path, process::ExitCode};

use clap::Command;
use notify::{RecursiveMode, Watcher};
use shadowsocks_rust::service::local;
use shadowsocks_service::local::domain_bloacker::{get_config_path, load_config, CONFIG_WATCHER};
fn main() -> ExitCode {
    let mut app = Command::new("shadowsocks")
        .version(shadowsocks_rust::VERSION)
        .about("A fast tunnel proxy that helps you bypass firewalls. (https://shadowsocks.org)");
    app = local::define_command_line_options(app);

    let matches = app.get_matches();
    let config_path = get_config_path();
    load_config();
    let p = std::fs::canonicalize(Path::new(&config_path)).unwrap();
    let mut watcher = unsafe { CONFIG_WATCHER.lock().unwrap() };
    watcher.watch(p.as_path(), RecursiveMode::NonRecursive).unwrap();
    local::main(&matches)
}
