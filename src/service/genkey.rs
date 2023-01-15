//! Generate sufficient key for method

use std::process::ExitCode;

use base64::Engine as _;
use clap::{builder::PossibleValuesParser, Arg, ArgAction, ArgMatches, Command};
use rand::RngCore;

use shadowsocks_service::shadowsocks::crypto::{available_ciphers, CipherKind};

/// Defines command line options
pub fn define_command_line_options(mut app: Command) -> Command {
    app = app.arg(
        Arg::new("ENCRYPT_METHOD")
            .short('m')
            .long("encrypt-method")
            .num_args(1)
            .action(ArgAction::Set)
            .required(true)
            .value_parser(PossibleValuesParser::new(available_ciphers()))
            .help("Server's encryption method"),
    );

    app
}

/// Program entrance `main`
pub fn main(matches: &ArgMatches) -> ExitCode {
    let method = matches
        .get_one::<String>("ENCRYPT_METHOD")
        .map(|x| x.parse::<CipherKind>().expect("method"))
        .expect("`method` is required");

    let key_len = method.key_len();
    if key_len > 0 {
        let mut key = vec![0u8; key_len];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut key);

        let encoded_key = base64::engine::general_purpose::STANDARD.encode(&key);
        println!("{encoded_key}");
    }

    ExitCode::SUCCESS
}
