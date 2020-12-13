#![crate_type = "lib"]

pub use self::{
    config::{ManagerAddr, ServerAddr, ServerConfig},
    manager::{ManagerClient, ManagerListener},
    relay::{
        tcprelay::{
            client::Socks5Client as TcpSocks5Client,
            proxy_listener::ProxyListener,
            proxy_stream::ProxyClientStream,
        },
        udprelay::{client::Socks5Client as UdpSocks5Client, proxy_socket::ProxySocket},
    },
};

pub use shadowsocks_crypto as crypto;

pub mod config;
pub mod context;
pub mod dns_resolver;
pub mod manager;
pub mod net;
pub mod plugin;
pub mod relay;
