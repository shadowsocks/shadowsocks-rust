//! Command line argument validator

#![allow(dead_code)]

use std::net::SocketAddr;

use shadowsocks::{relay::socks5::Address, ManagerAddr, ServerAddr, ServerConfig};

macro_rules! validate_type {
    ($name:ident, $ty:ty, $help:expr) => {
        pub fn $name(v: String) -> Result<(), String> {
            match v.parse::<$ty>() {
                Ok(..) => Ok(()),
                Err(..) => Err($help.to_owned()),
            }
        }
    };
}

validate_type!(
    validate_server_addr,
    ServerAddr,
    "should be either ip:port or domain:port"
);
validate_type!(validate_socket_addr, SocketAddr, "should be ip:port");
validate_type!(validate_address, Address, "should be either ip:port or domain:port");
validate_type!(
    validate_manager_addr,
    ManagerAddr,
    "should be either ip:port, domain:port or /path/to/unix.sock"
);
validate_type!(validate_u64, u64, "should be unsigned integer");

pub fn validate_server_url(v: String) -> Result<(), String> {
    match ServerConfig::from_url(&v) {
        Ok(..) => Ok(()),
        Err(..) => Err("should be SIP002 (https://shadowsocks.org/en/spec/SIP002-URI-Scheme.html) format".to_owned()),
    }
}
