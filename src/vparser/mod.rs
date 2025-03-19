//! Command line argument validator

#![allow(dead_code)]

use std::net::{IpAddr, SocketAddr};

#[cfg(any(feature = "local-tun", feature = "local-fake-dns"))]
use ipnet::IpNet;
#[cfg(feature = "local-redir")]
use shadowsocks_service::config::RedirType;
#[cfg(feature = "local-dns")]
use shadowsocks_service::local::dns::NameServerAddr;
use shadowsocks_service::{
    config::{ManagerServerHost, ManagerServerMode},
    shadowsocks::{ManagerAddr, ServerAddr, ServerConfig, crypto::CipherKind, relay::socks5::Address},
};

macro_rules! value_parser_type {
    ($name:ident, $ty:ty, $help:expr) => {
        pub fn $name(v: &str) -> Result<$ty, String> {
            match v.parse::<$ty>() {
                Ok(t) => Ok(t),
                Err(..) => Err($help.to_owned()),
            }
        }
    };
}

value_parser_type!(parse_server_addr, ServerAddr, "should be either ip:port or domain:port");
value_parser_type!(parse_ip_addr, IpAddr, "should be a valid IPv4 or IPv6 address");
value_parser_type!(parse_socket_addr, SocketAddr, "should be ip:port");
value_parser_type!(parse_address, Address, "should be either ip:port or domain:port");
value_parser_type!(
    parse_manager_addr,
    ManagerAddr,
    "should be either ip:port, domain:port or /path/to/unix.sock"
);
value_parser_type!(parse_manager_server_host, ManagerServerHost, "invalid server-host");
value_parser_type!(
    parse_manager_server_mode,
    ManagerServerMode,
    "should be \"builtin\" or \"standalone\""
);
#[cfg(feature = "local-dns")]
value_parser_type!(
    parse_name_server_addr,
    NameServerAddr,
    "should be either ip:port or a path to unix domain socket"
);
value_parser_type!(parse_cipher_kind, CipherKind, "invalid cipher");

pub fn parse_server_url(v: &str) -> Result<ServerConfig, String> {
    match ServerConfig::from_url(v) {
        Ok(t) => Ok(t),
        Err(..) => Err("should be SIP002 (https://shadowsocks.org/doc/sip002.html) format".to_owned()),
    }
}

#[cfg(any(feature = "local-tun", feature = "local-fake-dns"))]
pub fn parse_ipnet(v: &str) -> Result<IpNet, String> {
    match v.parse::<IpNet>() {
        Err(..) => Err("should be a CIDR address like 10.1.2.3/24".to_owned()),
        Ok(n) => Ok(n),
    }
}

#[cfg(feature = "local-redir")]
value_parser_type!(parse_redir_type, RedirType, "invalid redir-type");
