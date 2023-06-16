//! This is a binary running in the server environment
//!
//! You have to provide all needed configuration attributes via command line parameters,
//! or you could specify a configuration file. The format of configuration file is defined
//! in mod `config`.
//!
//! *It should be notice that the extended configuration file is not suitable for the server
//! side.*

use std::process::ExitCode;

use clap::Command;
use shadowsocks_rust::service::server;

fn main() -> ExitCode {
    let mut app = Command::new("shadowsocks")
        .version(shadowsocks_rust::VERSION)
        .about("A fast tunnel proxy that helps you bypass firewalls. (https://shadowsocks.org)");
    app = server::define_command_line_options(app);

    let matches = app.get_matches();
    server::main(&matches)
}
