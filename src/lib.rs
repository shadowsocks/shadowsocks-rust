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

//! shadowsocks is a fast tunnel proxy that helps you bypass firewalls.
//!
//! Currently it supports SOCKS5 and HTTP Proxy protocol.
//!
//! ## Usage
//!
//! Build shadowsocks and you will get at least 2 binaries: `sslocal` and `ssserver`
//!
//! Write your servers in a configuration file. Format is defined in
//! [shadowsocks' documentation](https://github.com/shadowsocks/shadowsocks/wiki)
//!
//! For example:
//!
//! ```json
//! {
//!    "server": "my_server_ip",
//!    "server_port": 8388,
//!    "local_address": "127.0.0.1",
//!    "local_port": 1080,
//!    "password": "mypassword",
//!    "timeout": 300,
//!    "method": "aes-256-cfb"
//! }
//! ```
//!
//! Save it in file `shadowsocks.json` and run local proxy server with
//!
//! ```bash
//! cargo run --bin sslocal -- -c shadowsocks.json
//! ```
//!
//! Now you can use SOCKS5 protocol to proxy your requests, for example:
//!
//! ```bash
//! curl --socks5-hostname 127.0.0.1:1080 https://www.google.com
//! ```
//!
//! On the server side, you can run the server with
//!
//! ```bash
//! cargo run --bin ssserver -- -c shadowsocks.json
//! ```
//!
//! Server should use the same configuration file as local, except the listen addresses for servers must be socket
//! addresses.
//!
//! Of course, you can also use `cargo install` to install binaries.
//!
//! ## API Usage
//!
//! Example to write a local server
//!
//! ```no_run
//! use shadowsocks::{Config, ConfigType, run_local};
//!
//! let config = Config::load_from_file("shadowsocks.json", ConfigType::Local).unwrap();
//! run_local(config).unwrap();
//! ```
//!
//! That's all! And let me show you how to run a proxy server
//!
//! ```no_run
//! use shadowsocks::{Config, ConfigType, run_server};
//!
//! let config = Config::load_from_file("shadowsocks.json", ConfigType::Server).unwrap();
//! run_server(config).unwrap();
//! ```
//!

#![crate_type = "lib"]
#![crate_name = "shadowsocks"]

extern crate serde_json;
#[macro_use]
extern crate log;
extern crate lru_cache;

extern crate byteorder;
extern crate rand;

extern crate crypto as rust_crypto;
extern crate ip;
extern crate openssl;
extern crate hyper;
extern crate url;
extern crate httparse;

extern crate futures;
extern crate futures_cpupool;
#[macro_use]
extern crate tokio_core;
extern crate net2;

extern crate libc;
#[macro_use]
extern crate lazy_static;

/// ShadowSocks version
pub const VERSION: &'static str = env!("CARGO_PKG_VERSION");

pub use self::config::{Config, ServerConfig, ServerAddr, ClientConfig, ConfigType};
pub use self::relay::local::run as run_local;
pub use self::relay::server::run as run_server;
pub use self::relay::tcprelay::client::Socks5Client;

pub mod config;
pub mod relay;
pub mod crypto;
