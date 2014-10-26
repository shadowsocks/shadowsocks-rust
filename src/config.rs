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

//! This is a mod for storing and parsing configuration
//!
//! According to shadowsocks' official documentation, the standard configuration
//! file should be in JSON format:
//!
//! ```ignore
//! {
//!     "server": "127.0.0.1",
//!     "server_port": 1080,
//!     "local_port": 8388,
//!     "password": "the-password",
//!     "timeout": 300,
//!     "method": "aes-256-cfb",
//!     "local_address": "127.0.0.1",
//!     "fast_open": false
//!     "dns_cache_capacity": 65536,
//! }
//! ```
//!
//! But this configuration is not for using multiple shadowsocks server, so we
//! introduce an extended configuration file format:
//!
//! ```ignore
//! {
//!     "servers": [
//!         {
//!             "address": "127.0.0.1",
//!             "port": 1080,
//!             "password": "hellofuck",
//!             "method": "bf-cfb"
//!             "dns_cache_capacity": 65536,
//!         },
//!         {
//!             "address": "127.0.0.1",
//!             "port": 1081,
//!             "password": "hellofuck",
//!             "method": "aes-128-cfb"
//!         }
//!     ],
//!     "local_port": 8388,
//!     "local_address": "127.0.0.1",
//!     "fast_open": false
//! }
//! ```
//!
//! These defined server will be used with a load balancing algorithm.
//!

extern crate serialize;

use serialize::json;
use std::io::{File, Read, Open};
use std::io::net::ip::{Port, SocketAddr};

use std::to_string::ToString;

use std::option::Option;

use crypto::cipher::CIPHER_AES_256_CFB;

pub const DEFAULT_DNS_CACHE_CAPACITY: uint = 65536;

/// Configuration for a server
#[deriving(Clone, Show)]
pub struct ServerConfig {
    pub address: String,
    pub port: Port,
    pub password: String,
    pub method: String,
    pub timeout: Option<u64>,
    pub dns_cache_capacity: uint,
}

#[deriving(Clone, Show)]
pub enum ServerConfigVariant {
    SingleServer(ServerConfig),
    MultipleServer(Vec<ServerConfig>),
}

#[deriving(Clone, Show)]
pub type ClientConfig = SocketAddr;

#[deriving(Clone, Show)]
pub struct Config {
    pub server: Option<ServerConfigVariant>,
    pub local: Option<ClientConfig>,
    pub fast_open: bool,
}

impl Config {
    pub fn new() -> Config {
        Config {
            server: None,
            local: None,
            fast_open: false,
        }
    }

    fn parse_json_object(o: &json::JsonObject) -> Option<Config> {
        let mut config = Config::new();

        if o.contains_key(&"servers".to_string()) {
            let server_list = o.find(&"servers".to_string()).unwrap()
                .as_list().expect("servers should be a list");

            let mut servers = Vec::new();
            for server in server_list.iter() {
                let mut method = server.find(&"method".to_string()).expect("You need to specify a method")
                                        .as_string().expect("method should be a string");
                if method == "" {
                    method = CIPHER_AES_256_CFB;
                }

                let server_cfg = ServerConfig {
                    address: server.find(&"address".to_string()).expect("You need to specify a server address")
                                        .as_string().expect("address should be a string").to_string(),
                    port: server.find(&"port".to_string()).expect("You need to specify a server port")
                                        .as_u64().expect("port should be an integer") as Port,
                    password: server.find(&"password".to_string()).expect("You need to specify a password")
                                        .as_string().expect("password should be a string").to_string(),
                    method: method.to_string(),
                    timeout: match server.find(&"timeout".to_string()) {
                        Some(t) => Some(t.as_u64().expect("timeout should be an integer") * 1000),
                        None => None,
                    },
                    dns_cache_capacity: match server.find(&"dns_cache_capacity".to_string()) {
                        Some(t) => t.as_u64().expect("dns_cache_capacity should be an integer") as uint,
                        None => DEFAULT_DNS_CACHE_CAPACITY,
                    },
                };
                servers.push(server_cfg);
            }

            config.server = Some(MultipleServer(servers));

        } else if o.contains_key(&"server".to_string())
                && o.contains_key(&"server_port".to_string())
                && o.contains_key(&"password".to_string())
                && o.contains_key(&"method".to_string()) {
            // Traditional configuration file
            let timeout = match o.find(&"timeout".to_string()) {
                Some(t) => Some(t.as_u64().expect("timeout should be an integer") * 1000),
                None => None,
            };

            let mut method = o.find(&"method".to_string()).unwrap()
                    .as_string().expect("method should be a string");
            if method == "" {
                method = CIPHER_AES_256_CFB;
            }

            let single_server = SingleServer(ServerConfig {
                address: o.find(&"server".to_string()).unwrap()
                    .as_string().expect("server should be a string").to_string(),
                port: o.find(&"server_port".to_string()).unwrap()
                    .as_u64().expect("server_port should be an integer") as Port,
                password: o.find(&"password".to_string()).unwrap()
                    .as_string().expect("password should be a string").to_string(),
                method: method.to_string(),
                timeout: timeout,
                dns_cache_capacity: match o.find(&"dns_cache_capacity".to_string()) {
                    Some(t) => t.as_u64().expect("cache_capacity should be an integer") as uint,
                    None => DEFAULT_DNS_CACHE_CAPACITY,
                },
            });

            config.server = Some(single_server);
        }

        if o.contains_key(&"local_address".to_string()) && o.contains_key(&"local_port".to_string()) {
            config.local = match o.find(&"local_address".to_string()) {
                Some(local_addr) => {
                    Some(SocketAddr {
                        ip: from_str(local_addr.as_string().expect("`local_address` should be a string"))
                            .expect("`local_address` is not a valid IP address"),
                        port: o.find(&"local_port".to_string()).unwrap()
                            .as_u64().expect("`local_port` should be an integer") as Port,
                    })
                },
                None => None,
            };
        } else if !o.contains_key(&"local_address".to_string()) && !o.contains_key(&"local_port".to_string()) {
            // Do nothing
        } else {
            fail!("You have to provide `local_address` and `local_port` together");
        }

        config.fast_open = match o.find(&"fast_open".to_string()) {
            Some(fo) => fo.as_boolean().expect("fast_open should be an boolean value"),
            None => false,
        };

        Some(config)
    }

    pub fn load_from_str(s: &str) -> Option<Config> {
        let object = match json::from_str(s) {
            Ok(obj) => { obj },
            Err(..) => return None,
        };

        let json_object = match object.as_object() {
            Some(obj) => { obj },
            None => return None,
        };

        Config::parse_json_object(json_object)
    }

    pub fn load_from_file(filename: &str) -> Option<Config> {
        let mut readeropt = File::open_mode(&Path::new(filename), Open, Read);

        let reader = match readeropt {
            Ok(ref mut r) => r,
            Err(..) => return None,
        };

        let object = match json::from_reader(reader) {
            Ok(obj) => { obj },
            Err(..) => return None,
        };

        let json_object = match object.as_object() {
            Some(obj) => obj,
            None => return None,
        };

        Config::parse_json_object(json_object)
    }
}
