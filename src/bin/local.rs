// The MIT License (MIT)

// Copyright (c) 2014 Y. T. CHUNG

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

/* code */

#![feature(phase)]

extern crate getopts;
extern crate shadowsocks;
#[phase(plugin, link)]
extern crate log;

use getopts::{optopt, optflag, getopts, usage};

use std::os;

use shadowsocks::config::Config;
use shadowsocks::relay::TcpRelayLocal;
use shadowsocks::relay::Relay;
use shadowsocks::crypto::cipher::CIPHER_AES_256_CFB;

fn main() {
    let opts = [
        optflag("v", "version", "print version"),
        optflag("h", "help", "print this message"),
        optopt("c", "config", "specify config file", "config.json"),
        optopt("s", "server-addr", "server address", ""),
        optopt("b", "local-addr", "local address, listen only to this address if specified", ""),
        optopt("k", "password", "password", ""),
        optopt("p", "server-port", "server port", ""),
        optopt("l", "local-port", "local socks5 proxy port", ""),
        optopt("m", "encrypt-method", "entryption method", CIPHER_AES_256_CFB),
    ];

    let matches = getopts(os::args().tail(), opts).unwrap();

    if matches.opt_present("h") {
        println!("{}", usage(format!("Usage: {} [Options]", os::args()[0]).as_slice(),
                            opts));
        return;
    }

    if matches.opt_present("v") {
        println!("{}", shadowsocks::VERSION);
        return;
    }

    let mut config =
        if matches.opt_present("c") {
            Config::load_from_file(matches.opt_str("c")
                                            .unwrap().as_slice()).unwrap()
        } else {
            match Config::load_from_file("config.json") {
                Some(c) => c,
                None => {
                    error!("Cannot find any `config.json` under current directory");
                    error!("You have to specify a config file");
                    return;
                }
            }
        };

    if matches.opt_present("s") {
        let server_ip = matches.opt_str("s").unwrap();
        config.server = server_ip;
    }
    if matches.opt_present("b") {
        let local_ip = matches.opt_str("b").unwrap();
        config.local = local_ip;
    }
    if matches.opt_present("k") {
        let passwd = matches.opt_str("k").unwrap();
        config.password = passwd;
    }
    if matches.opt_present("p") {
        let server_port = matches.opt_str("p").unwrap();
        config.server_port = from_str(server_port.as_slice()).unwrap();
    }
    if matches.opt_present("l") {
        let local_port = matches.opt_str("l").unwrap();
        config.local_port = from_str(local_port.as_slice()).unwrap();
    }
    if matches.opt_present("m") {
        let mut encrypt_meth = matches.opt_str("m").unwrap();
        if encrypt_meth.as_slice() == "" {
            encrypt_meth = CIPHER_AES_256_CFB.to_string();
        }

        config.method = encrypt_meth;
    }

    info!("ShadowSocks {}", shadowsocks::VERSION);

    debug!("Config: {}", config)

    TcpRelayLocal::new(config).run();
}
