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
//! use tokio::runtime::Runtime;
//! use shadowsocks::{run_local, Config, ConfigType};
//!
//! let mut rt = Runtime::new().expect("Failed to create runtime");
//! let rt_handle = rt.handle().clone();
//!
//! let config = Config::load_from_file("shadowsocks.json", ConfigType::Socks5Local).unwrap();
//! rt.block_on(run_local(config, rt_handle));
//! ```
//!
//! That's all! And let me show you how to run a proxy server
//!
//! ```no_run
//! use tokio::runtime::Runtime;
//! use shadowsocks::{run_server, Config, ConfigType};
//!
//! let mut rt = Runtime::new().expect("Failed to create runtime");
//! let rt_handle = rt.handle().clone();
//!
//! let config = Config::load_from_file("shadowsocks.json", ConfigType::Server).unwrap();
//! rt.block_on(run_server(config, rt_handle));
//! ```

#![crate_type = "lib"]
#![crate_name = "shadowsocks"]
#![recursion_limit = "128"]

use std::io;

use tokio::runtime::Handle;

/// ShadowSocks version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use self::{
    config::{ClientConfig, Config, ConfigType, Mode, ServerAddr, ServerConfig},
    relay::{local::run as run_local, server::run as run_server, tcprelay::client::Socks5Client},
};

pub mod config;
mod context;
pub mod crypto;
pub mod plugin;
pub mod relay;

/// Start a ShadowSocks' server
///
/// For `config.config_type` in `Socks5Local`, `HttpLocal` and `TunnelLocal`, server will run in Local mode.
pub async fn run(config: Config, rt: Handle) -> io::Result<()> {
    match config.config_type {
        ConfigType::Socks5Local | ConfigType::HttpLocal | ConfigType::TunnelLocal => run_local(config, rt).await,
        ConfigType::Server => run_server(config, rt).await,
    }
}
