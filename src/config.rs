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

use std::fs::OpenOptions;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, Ipv4Addr, Ipv6Addr};
use std::string::ToString;
use std::option::Option;
use std::default::Default;
use std::fmt::{self, Debug, Formatter};
use std::path::Path;
use std::collections::HashSet;

use ip::IpAddr;

use crypto::cipher::CipherType;

/// Default DNS cache capacity
pub const DEFAULT_DNS_CACHE_CAPACITY: usize = 65536;

/// Configuration for a server
#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub addr: String,
    pub port: u16,
    pub password: String,
    pub method: CipherType,
    pub timeout: Option<u32>,
    pub dns_cache_capacity: usize,
}

impl ServerConfig {
    pub fn basic(addr: String, port: u16, password: String, method: CipherType) -> ServerConfig {
        ServerConfig {
            addr: addr,
            port: port,
            password: password,
            method: method,
            timeout: None,
            dns_cache_capacity: DEFAULT_DNS_CACHE_CAPACITY,
        }
    }
}

impl json::ToJson for ServerConfig {
    fn to_json(&self) -> json::Json {
        use serialize::json::Json;
        let mut obj = json::Object::new();
        obj.insert("address".to_owned(), Json::String(self.addr.clone()));
        obj.insert("port".to_owned(), Json::U64(self.port as u64));
        obj.insert("password".to_owned(), Json::String(self.password.clone()));
        obj.insert("method".to_owned(), Json::String(self.method.to_string()));
        if let Some(t) = self.timeout {
            obj.insert("timeout".to_owned(), Json::U64(t as u64));
        }
        obj.insert("dns_cache_capacity".to_owned(),
                   Json::U64(self.dns_cache_capacity as u64));

        Json::Object(obj)
    }
}

/// Listening address
pub type ClientConfig = SocketAddr;

#[derive(Clone, Copy)]
pub enum ConfigType {
    Local,
    Server,
}

/// Configuration
#[derive(Clone, Debug)]
pub struct Config {
    pub server: Vec<ServerConfig>,
    pub local: Option<ClientConfig>,
    pub enable_udp: bool,
    pub timeout: Option<u32>,
    pub forbidden_ip: HashSet<IpAddr>,
}

impl Default for Config {
    fn default() -> Config {
        Config::new()
    }
}

#[derive(Copy, Clone)]
pub enum ErrorKind {
    MissingField,
    Malformed,
    Invalid,
    JsonParsingError,
    IoError,
}

/// Configuration parsing error
pub struct Error {
    pub kind: ErrorKind,
    pub desc: &'static str,
    pub detail: Option<String>,
}

impl Error {
    pub fn new(kind: ErrorKind, desc: &'static str, detail: Option<String>) -> Error {
        Error {
            kind: kind,
            desc: desc,
            detail: detail,
        }
    }
}

impl Debug for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self.detail {
            None => write!(f, "{}", self.desc),
            Some(ref det) => write!(f, "{} {}", self.desc, det),
        }
    }
}

impl Config {
    pub fn new() -> Config {
        Config {
            server: Vec::new(),
            local: None,
            enable_udp: false,
            timeout: None,
            forbidden_ip: HashSet::new(),
        }
    }

    fn parse_json_object(o: &json::Object, require_local_info: bool) -> Result<Config, Error> {
        let mut config = Config::new();

        config.timeout = match o.get(&"timeout".to_string()) {
            Some(t_str) => {
                Some(try!(t_str.as_u64()
                               .ok_or(Error::new(ErrorKind::Malformed,
                                                 "`timeout` should be an integer",
                                                 None))) as u32)
            }
            None => None,
        };

        if o.contains_key(&"servers".to_string()) {
            let server_list = try!(o.get(&"servers".to_string())
                                    .unwrap()
                                    .as_array()
                                    .ok_or(Error::new(ErrorKind::Malformed,
                                                      "`servers` should be a list",
                                                      None)));

            for server in server_list.iter() {
                let method_o = try!(server.find("method")
                                          .ok_or(Error::new(ErrorKind::MissingField,
                                                            "need to specify a method",
                                                            None)));
                let method_str = try!(method_o.as_string().ok_or(Error::new(ErrorKind::Malformed,
                                                                            "`method` should \
                                                                             be a string",
                                                                            None)));
                let method = try!(method_str.parse::<CipherType>().map_err(|_| {
                    Error::new(ErrorKind::Invalid,
                               "not supported method",
                               Some(format!("`{}` is not a supported method", method_str)))
                }));

                let addr_o = try!(server.find("address")
                                        .ok_or(Error::new(ErrorKind::MissingField,
                                                          "need to specify a server address",
                                                          None)));
                let addr_str = try!(addr_o.as_string()
                                          .ok_or(Error::new(ErrorKind::Malformed,
                                                            "`address` should be a string",
                                                            None)));

                let cfg = ServerConfig {
                    addr: addr_str.to_string(),
                    port: try!(try!(server.find("port")
                                          .ok_or(Error::new(ErrorKind::MissingField,
                                                            "need to specify a server port",
                                                            None)))
                                   .as_u64()
                                   .ok_or(Error::new(ErrorKind::Malformed,
                                                     "`port` should be an integer",
                                                     None))) as u16,
                    password: try!(try!(server.find("password")
                                              .ok_or(Error::new(ErrorKind::MissingField,
                                                                "need to specify a password",
                                                                None)))
                                       .as_string()
                                       .ok_or(Error::new(ErrorKind::Malformed,
                                                         "`password` should be a string",
                                                         None)))
                                  .to_string(),
                    method: method,
                    timeout: match server.find("timeout") {
                        Some(t) => Some(try!(t.as_u64()
                                              .ok_or(Error::new(ErrorKind::Malformed,
                                                                "`timeout` should be an integer",
                                                                None))) as u32),
                        None => None,
                    },
                    dns_cache_capacity: match server.find("dns_cache_capacity") {
                        Some(t) => {
                            try!(t.as_u64()
                                  .ok_or(Error::new(ErrorKind::Malformed,
                                                    "`dns_cache_capacity` should be an \
                                                     integer",
                                                    None))) as usize
                        }
                        None => DEFAULT_DNS_CACHE_CAPACITY,
                    },
                };

                config.server.push(cfg);
            }

        } else if o.contains_key(&"server".to_string()) && o.contains_key(&"server_port".to_string()) &&
           o.contains_key(&"password".to_string()) &&
           o.contains_key(&"method".to_string()) {
            // Traditional configuration file
            let method_o = try!(o.get(&"method".to_string())
                                 .ok_or(Error::new(ErrorKind::MissingField,
                                                   "need to specify method",
                                                   None)));
            let method_str = try!(method_o.as_string()
                                          .ok_or(Error::new(ErrorKind::Malformed,
                                                            "`method` should be a string",
                                                            None)));
            let method = try!(method_str.parse::<CipherType>()
                                        .map_err(|_| {
                                            Error::new(ErrorKind::Invalid,
                                                       "not supported method",
                                                       Some(format!("`{}` is not a supported \
                                                                     method",
                                                                    method_str)))
                                        }));
            let addr_o = try!(o.get(&"server".to_string())
                               .ok_or(Error::new(ErrorKind::MissingField,
                                                 "need to specify server address",
                                                 None)));
            let addr_str = try!(addr_o.as_string()
                                      .ok_or(Error::new(ErrorKind::Malformed,
                                                        "`server` should be a string",
                                                        None)));

            let single_server = ServerConfig {
                addr: addr_str.to_string(),
                port: try!(try!(o.get("server_port")
                                 .ok_or(Error::new(ErrorKind::MissingField,
                                                   "need to specify a server port",
                                                   None)))
                               .as_u64()
                               .ok_or(Error::new(ErrorKind::Malformed,
                                                 "`port` should be an integer",
                                                 None))) as u16,
                password: try!(try!(o.get("password")
                                     .ok_or(Error::new(ErrorKind::MissingField,
                                                       "need to specify a password",
                                                       None)))
                                   .as_string()
                                   .ok_or(Error::new(ErrorKind::Malformed,
                                                     "`password` should be a string",
                                                     None)))
                              .to_string(),
                method: method,
                timeout: match o.get("timeout") {
                    Some(t) => {
                        Some(try!(t.as_u64()
                                   .ok_or(Error::new(ErrorKind::Malformed,
                                                     "`timeout` should be an integer",
                                                     None))) as u32)
                    }
                    None => None,
                },
                dns_cache_capacity: match o.get("dns_cache_capacity") {
                    Some(t) => {
                        try!(t.as_u64()
                              .ok_or(Error::new(ErrorKind::Malformed,
                                                "`dns_cache_capacity` should be an integer",
                                                None))) as usize
                    }
                    None => DEFAULT_DNS_CACHE_CAPACITY,
                },
            };

            config.server = vec![single_server];
        }

        if require_local_info {
            let has_local_address = o.contains_key(&"local_address".to_string());
            let has_local_port = o.contains_key(&"local_port".to_string());

            if has_local_address && has_local_port {
                config.local = match o.get(&"local_address".to_string()) {
                    Some(local_addr) => {
                        let addr_str = try!(local_addr.as_string()
                                                      .ok_or(Error::new(ErrorKind::Malformed,
                                                                        "`local_address` \
                                                                         should be a string",
                                                                        None)));

                        let port =
                            try!(o.get(&"local_port".to_string())
                                  .unwrap()
                                  .as_u64()
                                  .ok_or(Error::new(ErrorKind::Malformed,
                                                    "`local_port` should be an integer",
                                                    None))) as u16;

                        match addr_str.parse::<Ipv4Addr>() {
                            Ok(ip) => Some(SocketAddr::V4(SocketAddrV4::new(ip, port))),
                            Err(..) => {
                                match addr_str.parse::<Ipv6Addr>() {
                                    Ok(ip) => {
                                        Some(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
                                    }
                                    Err(..) => {
                                        return Err(Error::new(ErrorKind::Malformed,
                                                              "`local_address` is not a valid IP \
                                                               address",
                                                              None))
                                    }
                                }
                            }
                        }
                    }
                    None => None,
                };
            } else if has_local_address ^ has_local_port {
                panic!("You have to provide `local_address` and `local_port` together");
            }
        }

        if let Some(forbidden_ip_conf) = o.get("forbidden_ip") {
            let forbidden_ip_arr = try!(forbidden_ip_conf.as_array()
                                                         .ok_or(Error::new(ErrorKind::Malformed,
                                                                           "`forbidden_ip` \
                                                                            should be a list",
                                                                           None)));
            config.forbidden_ip.extend(forbidden_ip_arr.into_iter().filter_map(|x| {
                let x = match x.as_string() {
                    Some(x) => x,
                    None => {
                        error!("Forbidden IP should be a string, but found {:?}, skipping",
                               x);
                        return None;
                    }
                };

                match x.parse::<IpAddr>() {
                    Ok(sock) => Some(sock),
                    Err(err) => {
                        error!("Invalid forbidden IP {}, {:?}, skipping", x, err);
                        return None;
                    }
                }
            }));
        }

        Ok(config)
    }

    pub fn load_from_str(s: &str, config_type: ConfigType) -> Result<Config, Error> {
        let object = match json::Json::from_str(s) {
            Ok(obj) => obj,
            Err(err) => {
                return Err(Error::new(ErrorKind::JsonParsingError,
                                      "json parse error",
                                      Some(format!("{:?}", err))));
            }
        };

        let json_object = match object.as_object() {
            Some(obj) => obj,
            None => {
                return Err(Error::new(ErrorKind::JsonParsingError,
                                      "root is not a JsonObject",
                                      None))
            }
        };

        Config::parse_json_object(json_object,
                                  match config_type {
                                      ConfigType::Local => true,
                                      ConfigType::Server => false,
                                  })
    }

    pub fn load_from_file(filename: &str, config_type: ConfigType) -> Result<Config, Error> {
        let mut readeropt = OpenOptions::new().read(true).open(&Path::new(filename));

        let reader = match readeropt {
            Ok(ref mut r) => r,
            Err(err) => {
                return Err(Error::new(ErrorKind::IoError,
                                      "error while reading file",
                                      Some(err.to_string())))
            }
        };

        let object = match json::Json::from_reader(reader) {
            Ok(obj) => obj,
            Err(err) => {
                return Err(Error::new(ErrorKind::JsonParsingError,
                                      "json parse error",
                                      Some(format!("{:?}", err))));
            }
        };

        let json_object = match object.as_object() {
            Some(obj) => obj,
            None => {
                return Err(Error::new(ErrorKind::JsonParsingError,
                                      "root is not a JsonObject",
                                      None))
            }
        };

        Config::parse_json_object(json_object,
                                  match config_type {
                                      ConfigType::Local => true,
                                      ConfigType::Server => false,
                                  })
    }
}

impl json::ToJson for Config {
    fn to_json(&self) -> json::Json {
        use serialize::json::Json;

        let mut obj = json::Object::new();
        if self.server.len() == 1 {
            // Official format
            obj.insert("server".to_owned(),
                       Json::String(self.server[0].addr.clone()));
            obj.insert("server_port".to_owned(),
                       Json::U64(self.server[0].port as u64));
            obj.insert("password".to_owned(),
                       Json::String(self.server[0].password.clone()));
            obj.insert("method".to_owned(),
                       Json::String(self.server[0].method.to_string()));
            if let Some(t) = self.server[0].timeout {
                obj.insert("timeout".to_owned(), Json::U64(t as u64));
            }
        } else {
            let arr: json::Array = self.server.iter().map(|s| s.to_json()).collect();
            obj.insert("servers".to_owned(), Json::Array(arr));
        }

        if let Some(l) = self.local {
            let ip_str = match &l {
                &SocketAddr::V4(ref v4) => v4.ip().to_string(),
                &SocketAddr::V6(ref v6) => v6.ip().to_string(),
            };

            obj.insert("local_address".to_owned(), Json::String(ip_str));
            obj.insert("local_port".to_owned(), Json::U64(l.port() as u64));
        }

        obj.insert("enable_udp".to_owned(), Json::Boolean(self.enable_udp));

        Json::Object(obj)
    }
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use serialize::json::ToJson;

        write!(f, "{}", self.to_json())
    }
}
