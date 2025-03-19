//! SIP002 and SIP008 URL Schemes
//!
//! SS-URI = "ss://" userinfo "@" hostname ":" port [ "/" ] [ "?" plugin ] [ "#" tag ]
//! userinfo = websafe-base64-encode-utf8(method  ":" password)

use std::process::ExitCode;

use clap::{Arg, ArgAction, Command, ValueHint};
use qrcode::{QrCode, types::Color};

use shadowsocks_service::{
    config::{Config, ConfigType, ServerInstanceConfig},
    shadowsocks::config::ServerConfig,
};

/// shadowsocks version
const VERSION: &str = env!("CARGO_PKG_VERSION");

const BLACK: &str = "\x1b[40m  \x1b[0m";
const WHITE: &str = "\x1b[47m  \x1b[0m";

fn print_qrcode(encoded: &str) {
    let qrcode = QrCode::new(encoded.as_bytes()).unwrap();

    for _ in 0..qrcode.width() + 2 {
        print!("{WHITE}");
    }
    println!();

    for y in 0..qrcode.width() {
        print!("{WHITE}");
        for x in 0..qrcode.width() {
            let color = match qrcode[(x, y)] {
                Color::Light => WHITE,
                Color::Dark => BLACK,
            };

            print!("{color}");
        }
        println!("{WHITE}");
    }

    for _ in 0..qrcode.width() + 2 {
        print!("{WHITE}");
    }
    println!();
}

fn encode(filename: &str, need_qrcode: bool) {
    let config = Config::load_from_file(filename, ConfigType::Server).unwrap();

    for svr in config.server {
        let encoded = svr.config.to_url();

        println!("{encoded}");

        if need_qrcode {
            let encoded = svr.config.to_qrcode_url();
            print_qrcode(&encoded);
        }
    }
}

fn decode(encoded: &str, need_qrcode: bool) {
    let svrconfig = ServerConfig::from_url(encoded).unwrap();

    let mut config = Config::new(ConfigType::Server);
    config.server.push(ServerInstanceConfig::with_server_config(svrconfig));

    println!("{config}");

    if need_qrcode {
        print_qrcode(encoded);
    }
}

#[cfg(feature = "utility-url-outline")]
fn decode_outline(remote: &str, need_qrcode: bool) {
    // Protect from using http and other non-ssconf links in reqwest call
    if !remote.starts_with("ssconf") {
        println!("Incorrect link format");
        return;
    }

    let url = remote.replace("ssconf", "https");
    let svrconfig = ServerConfig::from_url(reqwest::blocking::get(url).unwrap().text().unwrap().as_str()).unwrap();

    let mut config = Config::new(ConfigType::Server);
    config.server.push(ServerInstanceConfig::with_server_config(svrconfig));

    println!("{config}");

    if need_qrcode {
        print_qrcode(remote);
    }
}

fn main() -> ExitCode {
    let mut app = Command::new("ssurl")
        .version(VERSION)
        .about("Encode and decode ShadowSocks URL")
        .arg(
            Arg::new("ENCODE_CONFIG_PATH")
                .short('e')
                .long("encode")
                .action(ArgAction::Set)
                .value_hint(ValueHint::FilePath)
                .conflicts_with("DECODE_CONFIG_PATH")
                .required_unless_present_any(["DECODE_CONFIG_PATH", "OUTLINE_CONFIG_URL"])
                .help("Encode the server configuration in the provided JSON file"),
        )
        .arg(
            Arg::new("DECODE_CONFIG_PATH")
                .short('d')
                .long("decode")
                .action(ArgAction::Set)
                .value_hint(ValueHint::FilePath)
                .required_unless_present_any(["ENCODE_CONFIG_PATH", "OUTLINE_CONFIG_URL"])
                .help("Decode the server configuration from the provided ShadowSocks URL"),
        )
        .arg(
            Arg::new("QRCODE")
                .short('c')
                .long("qrcode")
                .action(ArgAction::SetTrue)
                .help("Generate the QRCode with the provided configuration"),
        );

    if cfg!(feature = "utility-url-outline") {
        app = app.arg(
            Arg::new("OUTLINE_CONFIG_URL")
                .short('o')
                .long("outline")
                .value_hint(ValueHint::Url)
                .required_unless_present_any(["ENCODE_CONFIG_PATH", "DECODE_CONFIG_PATH"])
                .help("Fetch and decode config from ssconf URL used by Outline"),
        );
    }

    let matches = app.get_matches();

    let need_qrcode = matches.get_flag("QRCODE");

    if let Some(file) = matches.get_one::<String>("ENCODE_CONFIG_PATH") {
        encode(file, need_qrcode);
        return ExitCode::SUCCESS;
    }

    if let Some(encoded) = matches.get_one::<String>("DECODE_CONFIG_PATH") {
        decode(encoded, need_qrcode);
        return ExitCode::SUCCESS;
    }

    #[cfg(feature = "utility-url-outline")]
    if let Some(remote) = matches.get_one::<String>("OUTLINE_CONFIG_URL") {
        decode_outline(remote, need_qrcode);
        return ExitCode::SUCCESS;
    }

    println!("Use -h for more detail");
    ExitCode::FAILURE
}
