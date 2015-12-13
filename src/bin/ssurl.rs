extern crate rustc_serialize;
extern crate clap;
extern crate shadowsocks;
extern crate qrcode;

use std::str;
use std::collections::HashSet;

use rustc_serialize::base64::{FromBase64, ToBase64, URL_SAFE};
use rustc_serialize::json::{ToJson, as_pretty_json};

use clap::{App, Arg};

use qrcode::QrCode;

use shadowsocks::config::{Config, ConfigType, ServerConfig};

const BLACK: &'static str = "\x1b[40m  \x1b[0m";
const WHITE: &'static str = "\x1b[47m  \x1b[0m";

fn encode_url(svr: &ServerConfig) -> String {
    let url = format!("{}:{}@{}:{}", svr.method.to_string(), svr.password, svr.addr, svr.port);
    format!("ss://{}", url.as_bytes().to_base64(URL_SAFE))
}

fn print_qrcode(encoded: &str) {
    let qrcode = QrCode::new(encoded.as_bytes()).unwrap();

    for _ in 0..qrcode.width()+2 {
        print!("{}", WHITE);
    }
    println!("");

    for y in 0..qrcode.width() {
        print!("{}", WHITE);
        for x in 0..qrcode.width() {
            let color = if qrcode[(x, y)] {
                BLACK
            } else {
                WHITE
            };

            print!("{}", color);
        }
        println!("{}", WHITE);
    }

    for _ in 0..qrcode.width()+2 {
        print!("{}", WHITE);
    }
    println!("");
}

fn encode(filename: &str, need_qrcode: bool) {
    let config = Config::load_from_file(filename, ConfigType::Server).unwrap();

    for svr in config.server {
        let encoded = encode_url(&svr);

        println!("{}", encoded);

        if need_qrcode {
            print_qrcode(&encoded);
        }
    }
}

fn decode(encoded: &str, need_qrcode: bool) {
    if !encoded.starts_with("ss://") {
        panic!("Malformed input: {:?}", encoded);
    }

    let decoded = encoded[5..].from_base64().unwrap();
    let decoded = str::from_utf8(&decoded).unwrap();

    let mut sp1 = decoded.split('@');
    let (account, addr) = match (sp1.next(), sp1.next()) {
        (Some(account), Some(addr)) => {
            (account, addr)
        },
        _ => panic!("Malformed input"),
    };

    let mut sp2 = account.split(':');
    let (method, pwd) = match (sp2.next(), sp2.next()) {
        (Some(m), Some(p)) => (m, p),
        _ => panic!("Malformed input"),
    };

    let mut sp3 = addr.split(':');
    let (addr, port) = match (sp3.next(), sp3.next()) {
        (Some(a), Some(p)) => (a, p),
        _ => panic!("Malformed input"),
    };

    let svrconfig = ServerConfig::basic(addr.to_owned(), port.parse().unwrap(),
                                        pwd.to_owned(), method.parse().unwrap());

    let config = Config {
        server: vec![svrconfig],
        local: None,
        enable_udp: false,
        timeout: None,
        forbidden_ip: HashSet::new(),
    };

    let config_json = config.to_json();
    println!("{}", as_pretty_json(&config_json));

    if need_qrcode {
        print_qrcode(encoded);
    }
}

fn main() {
    let app = App::new("ssurl")
                    .author("Y. T. Chung <zonyitoo@gmail.com>")
                    .about("Encode and decode ShadowSocks URL")
                    .arg(Arg::with_name("ENCODE").short("e").long("encode")
                            .takes_value(true)
                            .help("Encode the server configuration in the provided JSON file"))
                    .arg(Arg::with_name("DECODE").short("d").long("decode")
                            .takes_value(true)
                            .help("Decode the server configuration from the provide ShadowSocks URL"))
                    .arg(Arg::with_name("QRCODE").short("c").long("qrcode")
                            .takes_value(false)
                            .help("Generate the QRCode with the provided configuration"));
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
