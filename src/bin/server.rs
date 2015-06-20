// The MIT License (MIT)

// Copyright (c) 2014 Y. T. CHUNG <zonyitoo@gmail.com>

// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

//! This is a binary running in the server environment
//!
//! You have to provide all needed configuration attributes via command line parameters,
//! or you could specify a configuration file. The format of configuration file is defined
//! in mod `config`.
//!
//! *It should be notice that the extented configuration file is not suitable for the server
//! side.*

#![feature(box_syntax)]

extern crate clap;
extern crate shadowsocks;
#[macro_use]
extern crate log;
extern crate fern;
extern crate time;

use clap::{App, Arg};

use shadowsocks::config::{Config, ServerConfig, self};
use shadowsocks::config::DEFAULT_DNS_CACHE_CAPACITY;
use shadowsocks::relay::{RelayServer, Relay};

fn main() {
    let matches = App::new("shadowsocks")
                    .version(shadowsocks::VERSION)
                    .author("Y. T. Chung <zonyitoo@gmail.com>")
                    .about("A fast tunnel proxy that helps you bypass firewalls.")
                    .arg(Arg::with_name("VERBOSE").short("v")
                            .multiple(true)
                            .help("Set the level of debug"))
                    .arg(Arg::with_name("ENABLE_UDP").short("u").long("enable-udp")
                            .help("Enable UDP relay"))
                    .arg(Arg::with_name("CONFIG").short("c").long("config")
                            .takes_value(true)
                            .help("Specify config file"))
                    .arg(Arg::with_name("SERVER_ADDR").short("s").long("server-addr")
                            .takes_value(true)
                            .help("Server address"))
                    .arg(Arg::with_name("SERVER_PORT").short("p").long("server-port")
                            .takes_value(true)
                            .help("Server port"))
                    .arg(Arg::with_name("LOCAL_ADDR").short("b").long("local-addr")
                            .takes_value(true)
                            .help("Local address, listen only to this address if specified"))
                    .arg(Arg::with_name("LOCAL_PORT").short("l").long("local-port")
                            .takes_value(true)
                            .help("Local port"))
                    .arg(Arg::with_name("PASSWORD").short("k").long("password")
                            .takes_value(true)
                            .help("Password"))
                    .arg(Arg::with_name("ENCRYPT_METHOD").short("m").long("encrypt-method")
                            .takes_value(true)
                            .help("Encryption method"))
                    .arg(Arg::with_name("THREADS").short("t").long("threads")
                            .takes_value(true)
                            .help("Threads in thread pool"))
                    .get_matches();

    let logger_config = |show_location| fern::DispatchConfig {
        format: Box::new(move|msg: &str, level: &log::LogLevel, location: &log::LogLocation| {
            if show_location {
                format!("[{}][{}] [{}] {}", time::now().strftime("%Y-%m-%d][%H:%M:%S").unwrap(),
                        level, location.__module_path, msg)
            } else {
                format!("[{}][{}] {}", time::now().strftime("%Y-%m-%d][%H:%M:%S").unwrap(), level, msg)
            }
        }),
        output: vec![fern::OutputConfig::stderr()],
        level: log::LogLevelFilter::Trace
    };

    match matches.occurrences_of("VERBOSE") {
        0 => fern::init_global_logger(logger_config(false), log::LogLevelFilter::Info).unwrap(),
        1 => fern::init_global_logger(logger_config(true), log::LogLevelFilter::Debug).unwrap(),
        _ => fern::init_global_logger(logger_config(true), log::LogLevelFilter::Trace).unwrap()
    }

    let mut config =
        match matches.value_of("CONFIG") {
            Some(cpath) => {
                match Config::load_from_file(cpath, config::ConfigType::Server) {
                    Ok(cfg) => cfg,
                    Err(err) => {
                        error!("{:?}", err);
                        return;
                    }
                }
            },
            None => Config::new()
        };

    if matches.value_of("SERVER_ADDR").is_some()
        && matches.value_of("SERVER_PORT").is_some()
        && matches.value_of("PASSWORD").is_some()
        && matches.value_of("ENCRYPT_METHOD").is_some()
    {
        let (svr_addr, svr_port, password, method) = matches.value_of("SERVER_ADDR")
            .and_then(|svr_addr| matches.value_of("SERVER_PORT")
                                        .map(|svr_port| (svr_addr, svr_port)))
            .and_then(|(svr_addr, svr_port)| matches.value_of("PASSWORD")
                                                    .map(|pwd| (svr_addr, svr_port, pwd)))
            .and_then(|(svr_addr, svr_port, pwd)| matches.value_of("ENCRYPT_METHOD")
                                                         .map(|m| (svr_addr, svr_port, pwd, m)))
            .unwrap();

        let sc = ServerConfig {
            addr: svr_addr.to_owned(),
            port: svr_port.parse().ok().expect("`port` should be an integer"),
            password: password.to_owned(),
            method: match method.parse() {
                Ok(m) => m,
                Err(err) => {
                    panic!("Does not support {:?} method: {:?}", method, err);
                }
            },
            timeout: None,
            dns_cache_capacity: DEFAULT_DNS_CACHE_CAPACITY,
        };

        config.server.push(sc);
    }
    else if matches.value_of("SERVER_ADDR").is_none()
        && matches.value_of("SERVER_PORT").is_none()
        && matches.value_of("PASSWORD").is_none()
        && matches.value_of("ENCRYPT_METHOD").is_none()
    {
        // Does not provide server config
    }
    else {
        panic!("`server-addr`, `server-port`, `method` and `password` should be provided together");
    }

    config.enable_udp = matches.value_of("ENABLE_UDP").is_some();

    if !cfg!(feature = "enable-udp") && config.enable_udp {
        error!("Please compile shadowsocks with --cfg feature=\"enable-udp\"");
        panic!("UDP relay is disabled");
    }

    info!("ShadowSocks {}", shadowsocks::VERSION);

    debug!("Config: {:?}", config);

    let threads = matches.value_of("THREADS").unwrap_or("1").parse::<usize>()
        .ok().expect("`threads` should be an integer");

    RelayServer::new(config).run(threads);
}
