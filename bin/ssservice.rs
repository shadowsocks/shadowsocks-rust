//! This is a binary running in both local and server environment
//!
//! You have to provide all needed configuration attributes via command line parameters,
//! or you could specify a configuration file. The format of configuration file is defined
//! in mod `config`.
//!
//! *It should be notice that the extended configuration file is not suitable for the server
//! side.*

use std::{env, path::Path};

use clap::{clap_app, AppSettings, SubCommand};
use shadowsocks_rust::service::{local, manager, server};

fn main() {
    let app = clap_app!(shadowsocks =>
        (version: shadowsocks_rust::VERSION)
        (about: "A fast tunnel proxy that helps you bypass firewalls. (https://shadowsocks.org)")
    );

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
        .subcommand(
            local::define_command_line_options(SubCommand::with_name("local")).about("Shadowsocks Local service"),
        )
        .subcommand(
            server::define_command_line_options(SubCommand::with_name("server")).about("Shadowsocks Server service"),
        )
        .subcommand(
            manager::define_command_line_options(SubCommand::with_name("manager"))
                .about("Shadowsocks Server Manager service"),
        )
        .get_matches();

    match matches.subcommand() {
        ("local", Some(matches)) => local::main(matches),
        ("server", Some(matches)) => server::main(matches),
        ("manager", Some(matches)) => manager::main(matches),
        (subcommand, _) => unreachable!("Unrecognized subcommand {}", subcommand),
    }
}
