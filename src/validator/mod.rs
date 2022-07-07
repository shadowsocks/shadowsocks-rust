//! Command line argument validator

#![allow(dead_code)]

use std::net::{IpAddr, SocketAddr};

#[cfg(feature = "local-tun")]
use ipnet::IpNet;
#[cfg(feature = "local-dns")]
use shadowsocks_service::local::dns::NameServerAddr;
use shadowsocks_service::shadowsocks::{relay::socks5::Address, ManagerAddr, ServerAddr, ServerConfig};

macro_rules! validate_type {
    ($name:ident, $ty:ty, $help:expr) => {
        pub fn $name(v: &str) -> Result<(), String> {
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
validate_type!(validate_ip_addr, IpAddr, "should be a valid IPv4 or IPv6 address");
validate_type!(validate_socket_addr, SocketAddr, "should be ip:port");
validate_type!(validate_address, Address, "should be either ip:port or domain:port");
validate_type!(
    validate_manager_addr,
    ManagerAddr,
    "should be either ip:port, domain:port or /path/to/unix.sock"
);
#[cfg(feature = "local-dns")]
validate_type!(
    validate_name_server_addr,
    NameServerAddr,
    "should be either ip:port or a path to unix domain socket"
);
validate_type!(validate_u64, u64, "should be unsigned integer");
validate_type!(validate_u32, u32, "should be unsigned integer");
validate_type!(validate_usize, usize, "should be unsigned integer");

pub fn validate_server_url(v: &str) -> Result<(), String> {
    match ServerConfig::from_url(v) {
        Ok(..) => Ok(()),
        Err(..) => Err("should be SIP002 (https://shadowsocks.org/guide/sip002.html) format".to_owned()),
    }
}

#[cfg(feature = "local-tun")]
pub fn validate_ipnet(v: &str) -> Result<(), String> {
    match v.parse::<IpNet>() {
        Err(..) => Err("should be a CIDR address like 10.1.2.3/24".to_owned()),
        Ok(n) => {
            if n.trunc() == n {
                Err("should be a valid CIDR address with a host like 10.1.2.3/24".to_owned())
            } else {
                Ok(())
            }
        }
    }
}
