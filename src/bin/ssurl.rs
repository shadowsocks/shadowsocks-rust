extern crate rustc_serialize;
extern crate clap;
extern crate shadowsocks;

use std::str;

use rustc_serialize::base64::{FromBase64, ToBase64, URL_SAFE};
use rustc_serialize::json::{ToJson, as_pretty_json};

use clap::{App, Arg};

use shadowsocks::config::{Config, ConfigType, ServerConfig};

fn encode(filename: &str) {
    let config = Config::load_from_file(filename, ConfigType::Server).unwrap();

    for svr in config.server {
        let url = format!("{}:{}@{}:{}", svr.method.to_string(), svr.password, svr.addr, svr.port);
        let encoded = format!("ss://{}", url.as_bytes().to_base64(URL_SAFE));

        println!("{}", encoded);
    }
}

fn decode(encoded: &str) {
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

    let svrconfig_json = svrconfig.to_json();
    println!("{}", as_pretty_json(&svrconfig_json));
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
                            .help("Decode the server configuration from the provide ShadowSocks URL"));
    let matches = app.get_matches();

    if let Some(file) = matches.value_of("ENCODE") {
        encode(file);
    } else if let Some(encoded) = matches.value_of("DECODE") {
        decode(encoded);
    } else {
        println!("Use -h for more detail");
    }
}
