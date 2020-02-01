use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
};

use mio::net::UdpSocket;
use socket2::Socket;

pub fn check_support_tproxy() -> io::Result<()> {
    let err = Error::new(
        ErrorKind::Other,
        "Current Platform doesn't support UDP transparent proxy",
    );
    Err(err)
}

pub fn set_socket_before_bind(_addr: &SocketAddr, _socket: &Socket) -> io::Result<()> {
    unimplemented!("Current Platform doesn't support UDP transparent proxy");
}

pub fn recv_from_with_destination(_socket: &UdpSocket, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    unimplemented!("Current Platform doesn't support UDP transparent proxy");
}
