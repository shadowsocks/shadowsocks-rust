//! SIP002 URL Scheme
//!
//! SS-URI = "ss://" userinfo "@" hostname ":" port [ "/" ] [ "?" plugin ] [ "#" tag ]
//! userinfo = websafe-base64-encode-utf8(method  ":" password)

extern crate clap;
extern crate qrcode;
extern crate serde_json;
extern crate shadowsocks;

use clap::{App, Arg};

use qrcode::QrCode;
use qrcode::types::Color;

use shadowsocks::VERSION;
use shadowsocks::config::{Config, ConfigType, ServerConfig};

const BLACK: &'static str = "\x1b[40m  \x1b[0m";
const WHITE: &'static str = "\x1b[47m  \x1b[0m";

fn print_qrcode(encoded: &str) {
    let qrcode = QrCode::new(encoded.as_bytes()).unwrap();

    for _ in 0..qrcode.width() + 2 {
        print!("{}", WHITE);
    }
    println!("");

    for y in 0..qrcode.width() {
        print!("{}", WHITE);
        for x in 0..qrcode.width() {
            let color = match qrcode[(x, y)] {
                Color::Light => WHITE,
                Color::Dark => BLACK,
            };

            print!("{}", color);
        }
        println!("{}", WHITE);
    }

    for _ in 0..qrcode.width() + 2 {
        print!("{}", WHITE);
    }
    println!("");
}

fn encode(filename: &str, need_qrcode: bool) {
    let config = Config::load_from_file(filename, ConfigType::Server).unwrap();

    for svr in config.server {
        let encoded = svr.to_url();

        println!("{}", encoded);

        if need_qrcode {
            let encoded = svr.to_qrcode_url();
            print_qrcode(&encoded);
        }
    }
}

fn decode(encoded: &str, need_qrcode: bool) {
    let svrconfig = ServerConfig::from_url(encoded).unwrap();

    let mut config = Config::new();
    config.server.push(svrconfig);

    let config_json = config.to_json();
    println!("{}", serde_json::to_string_pretty(&config_json).unwrap());

    if need_qrcode {
        print_qrcode(encoded);
    }
}

fn main() {
    let app = App::new("ssurl")
        .about("Encode and decode ShadowSocks URL")
        .version(VERSION)
        .arg(
            Arg::with_name("ENCODE")
                .short("e")
                .long("encode")
                .takes_value(true)
                .help("Encode the server configuration in the provided JSON file"),
        )
        .arg(
            Arg::with_name("DECODE")
                .short("d")
                .long("decode")
                .takes_value(true)
                .help("Decode the server configuration from the provide ShadowSocks URL"),
        )
        .arg(
            Arg::with_name("QRCODE")
                .short("c")
                .long("qrcode")
                .takes_value(false)
                .help("Generate the QRCode with the provided configuration"),
        );
    let matches = app.get_matches();

    let need_qrcode = matches.is_present("QRCODE");

    if let Some(file) = matches.value_of("ENCODE") {
        encode(file, need_qrcode);
    } else if let Some(encoded) = matches.value_of("DECODE") {
        decode(encoded, need_qrcode);
    } else {
        println!("Use -h for more detail");
    }
}
