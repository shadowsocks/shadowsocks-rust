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

extern crate getopts;
extern crate shadowsocks;
#[macro_use]
extern crate log;

#[cfg(feature = "enable-green")]
extern crate green;
#[cfg(feature = "enable-green")]
extern crate rustuv;

use getopts::{optopt, optflag, getopts, usage};
use std::os;
use std::io::net::addrinfo::get_host_addresses;
use std::io::net::ip::SocketAddr;

use shadowsocks::config::{Config, ServerConfig, ClientConfig, self};
use shadowsocks::config::DEFAULT_DNS_CACHE_CAPACITY;
use shadowsocks::relay::{RelayServer, Relay};
use shadowsocks::crypto::cipher::CIPHER_AES_256_CFB;

#[cfg(feature = "enable-green")]
#[warn(unstable)]
#[start]
fn start(argc: int, argv: *const *const u8) -> int {
    use rustuv::EventLoop;
    fn event_loop() -> Box<green::EventLoop + Send> {
        box EventLoop::new().unwrap() as Box<green::EventLoop + Send>
    }
    green::start(argc, argv, event_loop, main)
}

fn main() {
    let opts = [
        optflag("v", "version", "print version"),
        optflag("h", "help", "print this message"),
        optflag("u", "enable-udp", "enable UDP relay"),
        optopt("c", "config", "specify config file", "config.json"),
        optopt("s", "server-addr", "server address", ""),
        optopt("b", "local-addr", "local address, listen only to this address if specified", ""),
        optopt("k", "password", "password", ""),
        optopt("p", "server-port", "server port", ""),
        optopt("l", "local-port", "local socks5 proxy port", ""),
        optopt("m", "encrypt-method", "entryption method", CIPHER_AES_256_CFB),
    ];

    let matches = getopts(os::args().tail(), &opts).unwrap();

    if matches.opt_present("h") {
        println!("{}", usage(format!("Usage: {} [Options]", os::args()[0]).as_slice(),
                            &opts));
        return;
    }

    if matches.opt_present("v") {
        println!("{:?}", shadowsocks::VERSION);
        return;
    }

    let mut config =
        if matches.opt_present("c") {
            Config::load_from_file(matches.opt_str("c")
                                            .unwrap().as_slice(),
                                   config::ConfigType::Server).unwrap()
        } else {
            Config::new()
        };

    if matches.opt_present("s") && matches.opt_present("p") && matches.opt_present("k") && matches.opt_present("m") {
        let addr_str = matches.opt_str("s").unwrap();
        let sc = ServerConfig {
            addr: SocketAddr {
                ip: get_host_addresses(addr_str.as_slice()).unwrap()
                    .first().expect(format!("Unable to resolve {}", addr_str).as_slice()).clone(),
                port: matches.opt_str("p").unwrap().as_slice().parse().expect("`port` should be an integer"),
            },
            password: matches.opt_str("k").unwrap(),
            method: matches.opt_str("m").unwrap(),
            timeout: None,
            dns_cache_capacity: DEFAULT_DNS_CACHE_CAPACITY,
        };
        match config.server {
            Some(ref mut server) => {
                server.push(sc)
            },
            None => { config.server = Some(vec![sc]) },
        }
    } else if !matches.opt_present("s") && !matches.opt_present("b")
            && !matches.opt_present("k") && !matches.opt_present("m") {
        // Do nothing
    } else {
        panic!("`server`, `server_port`, `method` and `password` should be provided together");
    }

    if matches.opt_present("b") && matches.opt_present("l") {
        let local = ClientConfig {
            ip: matches.opt_str("b").unwrap().as_slice().parse().expect("`local` is not a valid IP address"),
            port: matches.opt_str("l").unwrap().as_slice().parse().expect("`local_port` should be an integer"),
        };
        config.local = Some(local)
    }

    config.enable_udp = matches.opt_present("u");

    if !cfg!(feature = "enable-udp") && config.enable_udp {
        error!("Please compile shadowsocks with --cfg feature=\"enable-udp\"");
        panic!("UDP relay is disabled");
    }

    info!("ShadowSocks {:?}", shadowsocks::VERSION);

    debug!("Config: {:?}", config);

    RelayServer::new(config).run();
}
