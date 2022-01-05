//! This is a binary running in both local and server environment
//!
//! You have to provide all needed configuration attributes via command line parameters,
//! or you could specify a configuration file. The format of configuration file is defined
//! in mod `config`.
//!
//! *It should be notice that the extended configuration file is not suitable for the server
//! side.*

use std::{env, path::Path};

use clap::{App, AppSettings};
use shadowsocks_rust::service::{local, manager, server};

fn main() {
    let app = App::new("shadowsocks")
        .version(shadowsocks_rust::VERSION)
        .about("A fast tunnel proxy that helps you bypass firewalls. (https://shadowsocks.org)");

    // Allow running `ssservice` as symlink of `sslocal`, `ssserver` and `ssmanager`
    if let Some(program_path) = env::args().next() {
        if let Some(program_name) = Path::new(&program_path).file_name() {
            match program_name.to_str() {
                Some("sslocal") => return local::main(&local::define_command_line_options(app).get_matches()),
                Some("ssserver") => return server::main(&local::define_command_line_options(app).get_matches()),
                Some("ssmanager") => return manager::main(&local::define_command_line_options(app).get_matches()),
                _ => {}
            }
        }
    }

    let matches = app
        .setting(AppSettings::SubcommandRequired)
        .subcommand(local::define_command_line_options(App::new("local")).about("Shadowsocks Local service"))
        .subcommand(server::define_command_line_options(App::new("server")).about("Shadowsocks Server service"))
        .subcommand(
            manager::define_command_line_options(App::new("manager")).about("Shadowsocks Server Manager service"),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("local", matches)) => local::main(matches),
        Some(("server", matches)) => server::main(matches),
        Some(("manager", matches)) => manager::main(matches),
        _ => unreachable!("expecting a subcommand"),
    }
}
