//! SOCKS5 Local Server

pub use self::{
    tcprelay::Socks5TcpHandler,
    udprelay::{Socks5UdpServer, Socks5UdpServerBuilder},
};

mod tcprelay;
mod udprelay;
