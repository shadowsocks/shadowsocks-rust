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
//!     "dns_cache_capacity": 65536
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
//!     "local_address": "127.0.0.1"
//! }
//! ```
//!
//! These defined server will be used with a load balancing algorithm.
//!

use serialize::json;

use std::io::{File, Read, Open};
use std::io::net::ip::{Port, SocketAddr};
use std::io::net::addrinfo::get_host_addresses;
use std::string::ToString;
use std::option::Option;
use std::default::Default;
use std::fmt::{Show, Formatter, self};

use crypto::cipher::CIPHER_AES_256_CFB;

pub const DEFAULT_DNS_CACHE_CAPACITY: usize = 65536;

/// Configuration for a server
#[derive(Clone, Show)]
pub struct ServerConfig {
    pub addr: SocketAddr,
    pub password: String,
    pub method: String,
    pub timeout: Option<u64>,
    pub dns_cache_capacity: usize,
}

pub type ClientConfig = SocketAddr;

#[derive(Clone, Copy)]
pub enum ConfigType {
    Local,
    Server
}

#[derive(Clone, Show)]
pub struct Config {
    pub server: Option<Vec<ServerConfig>>,
    pub local: Option<ClientConfig>,
    pub enable_udp: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config::new()
    }
}

pub struct Error {
    pub message: String,
}

impl Error {
    pub fn new(msg: &str) -> Error {
        Error {
            message: msg.to_string(),
        }
    }
}

impl Show for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

macro_rules! try_config{
    ($inp:expr, $errmsg:expr) => (
        match $inp {
            Some(s) => { s },
            None => { return Err(Error::new($errmsg)); },
        }
    );
}

impl Config {
    pub fn new() -> Config {
        Config {
            server: None,
            local: None,
            enable_udp: false,
        }
    }

    fn parse_json_object(o: &json::Object, require_local_info: bool) -> Result<Config, Error> {
        let mut config = Config::new();

        if o.contains_key(&"servers".to_string()) {
            let server_list = try_config!(o.get(&"servers".to_string()).unwrap()
                .as_array(), "servers should be a list");

            let mut servers = Vec::new();
            for server in server_list.iter() {
                let mut method = try_config!(
                                        try_config!(server.find("method"),
                                                    "You need to specify a method").as_string(),
                                        "method should be a string");
                if method == "" {
                    method = CIPHER_AES_256_CFB;
                }

                let addr_str = try_config!(
                                    try_config!(server.find("address"),
                                                "You need to specify a server address").as_string(),
                                    "address should be a string");

                let server_cfg = ServerConfig {
                    addr: SocketAddr {
                        ip: try_config!(get_host_addresses(addr_str).unwrap().first(),
                                        format!("Unable to resolve server {}", addr_str).as_slice()).clone(),
                        port: try_config!(
                                    try_config!(server.find("port"),
                                                "You need to specify a server port").as_u64(),
                                    "port should be an integer") as Port,
                    },
                    password: try_config!(
                                    try_config!(server.find("password"),
                                                "You need to specify a password").as_string(),
                                    "password should be a string").to_string(),
                    method: method.to_string(),
                    timeout: match server.find("timeout") {
                        Some(t) => Some(try_config!(t.as_u64(), "timeout should be an integer") * 1000),
                        None => None,
                    },
                    dns_cache_capacity: match server.find("dns_cache_capacity") {
                        Some(t) => try_config!(t.as_u64(), "dns_cache_capacity should be an integer") as usize,
                        None => DEFAULT_DNS_CACHE_CAPACITY,
                    },
                };
                servers.push(server_cfg);
            }

            config.server = Some(servers);

        } else if o.contains_key(&"server".to_string())
                && o.contains_key(&"server_port".to_string())
                && o.contains_key(&"password".to_string())
                && o.contains_key(&"method".to_string()) {
            // Traditional configuration file
            let timeout = match o.get(&"timeout".to_string()) {
                Some(t) => Some(try_config!(t.as_u64(), "timeout should be an integer") * 1000),
                None => None,
            };

            let mut method = try_config!(o.get(&"method".to_string()).unwrap().as_string(),
                                         "method should be a string");
            if method == "" {
                method = CIPHER_AES_256_CFB;
            }

            let addr_str = try_config!(o.get(&"server".to_string()).unwrap().as_string(),
                                       "server should be a string");

            let single_server = ServerConfig {
                addr: SocketAddr {
                    ip: try_config!(get_host_addresses(addr_str).unwrap().first(),
                                    format!("Unable to resolve server {}", addr_str).as_slice()).clone(),
                    port: try_config!(o.get(&"server_port".to_string()).unwrap().as_u64(),
                                      "server_port should be an integer") as Port,
                },
                password: try_config!(o.get(&"password".to_string()).unwrap().as_string(),
                                      "password should be a string").to_string(),
                method: method.to_string(),
                timeout: timeout,
                dns_cache_capacity: match o.get(&"dns_cache_capacity".to_string()) {
                    Some(t) => try_config!(t.as_u64(), "cache_capacity should be an integer") as usize,
                    None => DEFAULT_DNS_CACHE_CAPACITY,
                },
            };

            config.server = Some(vec![single_server]);
        }

        if require_local_info {
            let has_local_address = o.contains_key(&"local_address".to_string());
            let has_local_port = o.contains_key(&"local_port".to_string());

            if has_local_address && has_local_port {
                config.local = match o.get(&"local_address".to_string()) {
                    Some(local_addr) => {
                        Some(SocketAddr {
                            ip: try_config!(try_config!(local_addr.as_string(),
                                                                 "`local_address` should be a string").parse(),
                                            "`local_address` is not a valid IP address"),
                            port: try_config!(o.get(&"local_port".to_string()).unwrap().as_u64(),
                                              "`local_port` should be an integer") as Port,
                        })
                    },
                    None => None,
                };
            } else if has_local_address ^ has_local_port {
                panic!("You have to provide `local_address` and `local_port` together");
            }
        }

        Ok(config)
    }

    pub fn load_from_str(s: &str, config_type: ConfigType) -> Result<Config, Error> {
        let object = match json::Json::from_str(s) {
            Ok(obj) => { obj },
            Err(err) => {
                return Err(Error::new(format!("{:?}", err).as_slice()));
            }
        };

        let json_object = match object.as_object() {
            Some(obj) => { obj },
            None => return Err(Error::new("Root is not a JsonObject")),
        };

        Config::parse_json_object(json_object, match config_type {
            ConfigType::Local => true,
            ConfigType::Server => false
        })
    }

    pub fn load_from_file(filename: &str, config_type: ConfigType) -> Result<Config, Error> {
        let mut readeropt = File::open_mode(&Path::new(filename), Open, Read);

        let reader = match readeropt {
            Ok(ref mut r) => r,
            Err(err) => return Err(Error::new(err.to_string().as_slice())),
        };

        let object = match json::Json::from_reader(reader) {
            Ok(obj) => { obj },
            Err(err) => {
                return Err(Error::new(format!("{:?}", err).as_slice()));
            }
        };

        let json_object = match object.as_object() {
            Some(obj) => obj,
            None => return Err(Error::new("Root is not a JsonObject")),
        };

        Config::parse_json_object(json_object, match config_type {
            ConfigType::Local => true,
            ConfigType::Server => false
        })
    }
}
