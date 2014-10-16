#![feature(phase)]

extern crate getopts;
extern crate shadowsocks;
#[phase(plugin, link)]
extern crate log;

use getopts::{optopt, optflag, getopts, usage};
use std::os;

use shadowsocks::config::Config;
use shadowsocks::tcprelay::TcpRelayServer;
use shadowsocks::relay::Relay;

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
        optopt("m", "encrypt-method", "entryption method", "aes-256-cfb"),
    ];

    let matches = getopts(os::args().tail(), opts).unwrap();

    if matches.opt_present("h") {
        println!("{}", usage(format!("Usage: {} [options]", os::args()[0]).as_slice(),
                            opts));
        return;
    }

    if matches.opt_present("v") {
        println!("{}", shadowsocks::VERSION);
        return;
    }

    let mut config = if matches.opt_present("c") {
        Config::load_from_file(matches.opt_str("c")
                                        .unwrap().as_slice()).unwrap()
    } else {
        match Config::load_from_file("config.json") {
            Some(c) => c,
            None => {
                error!("Cannot find any `config.json` under current directory");
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
            encrypt_meth = "aes-256-cfb".to_string();
        }

        config.method = encrypt_meth;
    }

    info!("ShadowSocks {}", shadowsocks::VERSION);

    debug!("Config: {}", config)

    TcpRelayServer::new(&config).run();
}
