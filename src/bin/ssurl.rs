//! SIP002 URL Scheme
//!
//! SS-URI = "ss://" userinfo "@" hostname ":" port [ "/" ] [ "?" plugin ] [ "#" tag ]
//! userinfo = websafe-base64-encode-utf8(method  ":" password)

extern crate clap;
extern crate shadowsocks;
extern crate qrcode;
extern crate serde_json;
extern crate base64;
extern crate serde_urlencoded;
extern crate url;

use clap::{App, Arg};

use qrcode::QrCode;
use qrcode::types::Color;

use base64::{URL_SAFE_NO_PAD, decode_config, encode_config};

use url::Url;

use shadowsocks::VERSION;
use shadowsocks::config::{Config, ConfigType, ServerAddr, ServerConfig};
use shadowsocks::plugin::PluginConfig;

const BLACK: &'static str = "\x1b[40m  \x1b[0m";
const WHITE: &'static str = "\x1b[47m  \x1b[0m";

fn encode_url(svr: &ServerConfig) -> String {
    let user_info = format!("{}:{}", svr.method().to_string(), svr.password());
    let encoded_user_info = encode_config(&user_info, URL_SAFE_NO_PAD);

    let mut url = format!("ss://{}@{}", encoded_user_info, svr.addr());
    if let Some(c) = svr.plugin() {
        let mut plugin = c.plugin.clone();
        if let Some(ref opt) = c.plugin_opt {
            plugin += ";";
            plugin += opt;
        }

        let plugin_param = [("plugin", &plugin)];
        url += "/?";
        url += &serde_urlencoded::to_string(&plugin_param).unwrap();
    }

    url
}

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

    let parsed = Url::parse(encoded).expect("Failed to parse url");

    if parsed.scheme() != "ss" {
        panic!("Url must have scheme \"ss\", but found \"{}\"", parsed.scheme());
    }

    let user_info = parsed.username();
    let account = decode_config(user_info, URL_SAFE_NO_PAD).unwrap();
    let account = String::from_utf8(account).expect("UserInfo is not UTF-8 encoded");
    let host = parsed.host_str().expect("Url must have a host");
    let port = parsed.port().unwrap_or(8388);
    let addr = format!("{}:{}", host, port);

    let mut sp2 = account.split(':');
    let (method, pwd) = match (sp2.next(), sp2.next()) {
        (Some(m), Some(p)) => (m, p),
        _ => panic!("Malformed input"),
    };

    let addr = match addr.parse::<ServerAddr>() {
        Ok(a) => a,
        Err(err) => panic!("Malformed input: {:?}", err),
    };

    let mut plugin = None;
    if let Some(q) = parsed.query() {
        let query = serde_urlencoded::from_bytes::<Vec<(String, String)>>(q.as_bytes())
            .expect("Failed to parse query string");

        for (key, value) in query {
            if key != "plugin" {
                continue;
            }

            let mut vsp = value.splitn(2, ';');
            match vsp.next() {
                None => {}
                Some(p) => {
                    plugin = Some(PluginConfig {
                                      plugin: p.to_owned(),
                                      plugin_opt: vsp.next().map(ToOwned::to_owned),
                                  })
                }
            }
        }
    }

    let svrconfig = ServerConfig::new(addr, pwd.to_owned(), method.parse().unwrap(), None, plugin);

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
        .author("Y. T. Chung")
        .about("Encode and decode ShadowSocks URL")
        .version(VERSION)
        .arg(Arg::with_name("ENCODE")
                 .short("e")
                 .long("encode")
                 .takes_value(true)
                 .help("Encode the server configuration in the provided JSON file"))
        .arg(Arg::with_name("DECODE")
                 .short("d")
                 .long("decode")
                 .takes_value(true)
                 .help("Decode the server configuration from the provide ShadowSocks URL"))
        .arg(Arg::with_name("QRCODE")
                 .short("c")
                 .long("qrcode")
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
