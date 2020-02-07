use std::{
    io::{self, Error, ErrorKind},
    net::SocketAddr,
};

use mio::net::UdpSocket as MioUdpSocket;
use socket2::Socket;

pub fn check_support_tproxy() -> io::Result<()> {
    // Windows seems to support transparent proxy, but I haven't found any useful document about it

    let err = Error::new(ErrorKind::Other, "Windows doesn't support UDP transparent proxy");
    Err(err)
}

pub fn set_socket_before_bind(_addr: &SocketAddr, _socket: &Socket) -> io::Result<()> {
    unimplemented!("Windows doesn't support UDP transparent proxy");
}

pub fn recv_from_with_destination(
    _socket: &MioUdpSocket,
    _buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    unimplemented!("Windows doesn't support UDP transparent proxy");
}
