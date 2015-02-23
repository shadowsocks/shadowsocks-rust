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

//! This is a binary runing in the local environment
//!
//! You have to provide all needed configuration attributes via command line parameters,
//! or you could specify a configuration file. The format of configuration file is defined
//! in mod `config`.
//!

#![feature(env, net)]

extern crate getopts;
extern crate shadowsocks;
#[macro_use]
extern crate log;

use getopts::Options;

use std::env;
use std::net::SocketAddr;

use shadowsocks::config::{Config, ServerConfig, self};
use shadowsocks::config::DEFAULT_DNS_CACHE_CAPACITY;
use shadowsocks::relay::{RelayLocal, Relay};

fn main() {
    let mut opts = Options::new();
    opts.optflag("v", "version", "print version");
    opts.optflag("h", "help", "print this message");
    opts.optflag("u", "enable-udp", "enable UDP relay");
    opts.optopt("c", "config", "specify config file", "config.json");
    opts.optopt("s", "server-addr", "server address", "");
    opts.optopt("b", "local-addr", "local address, listen only to this address if specified", "");
    opts.optopt("k", "password", "password", "");
    opts.optopt("p", "server-port", "server port", "");
    opts.optopt("l", "local-port", "local socks5 proxy port", "");
    opts.optopt("m", "encrypt-method", "entryption method", "aes-256-cfb");

    let matches = opts.parse(env::args().skip(1)).unwrap();

    if matches.opt_present("h") {
        println!("{}", opts.usage(&format!("Usage: {} [Options]", env::args().next().unwrap())[..]));
        return;
    }

    if matches.opt_present("v") {
        println!("{:?}", shadowsocks::VERSION);
        return;
    }

    let mut config =
        if matches.opt_present("c") {
            let cfile = matches.opt_str("c").unwrap();
            match Config::load_from_file(&cfile[..], config::ConfigType::Local) {
                Ok(cfg) => cfg,
                Err(err) => {
                    error!("{:?}", err);
                    return;
                }
            }
        } else {
            Config::new()
        };

    if matches.opt_present("s") && matches.opt_present("p") && matches.opt_present("k") && matches.opt_present("m") {
        let addr_str = matches.opt_str("s").unwrap();
        let sc = ServerConfig {
            addr: addr_str,
            port: matches.opt_str("p").unwrap().parse().ok().expect("`port` should be an integer"),
            password: matches.opt_str("k").unwrap(),
            method: match matches.opt_str("m") {
                Some(method_s) => {
                    match method_s.parse() {
                        Ok(m) => m,
                        Err(err) => panic!("`{}` is not a supported method: {:?}", method_s, err),
                    }
                },
                None => panic!("failed to get method string"),
            },
            timeout: None,
            dns_cache_capacity: DEFAULT_DNS_CACHE_CAPACITY,
        };
        config.server.push(sc);
    } else if !matches.opt_present("s") && !matches.opt_present("b")
            && !matches.opt_present("k") && !matches.opt_present("m") {
        // Do nothing
    } else {
        panic!("`server`, `server_port`, `method` and `password` should be provided together");
    }

    if matches.opt_present("b") && matches.opt_present("l") {
        let local = SocketAddr::new(
            matches.opt_str("b").unwrap().parse().ok().expect("`local` is not a valid IP address"),
            matches.opt_str("l").unwrap().parse().ok().expect("`local_port` should be an integer"),
        );
        config.local = Some(local)
    }

    config.enable_udp = matches.opt_present("u");

    info!("ShadowSocks {:?}", shadowsocks::VERSION);

    debug!("Config: {:?}", config);

    RelayLocal::new(config).run();
}
