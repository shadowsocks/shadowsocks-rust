use std::{
    io::{self, Error, ErrorKind},
    net::SocketAddr,
};

use mio::net::UdpSocket;
use socket2::Socket;

pub fn check_support_tproxy() -> io::Result<()> {
    // FIXME: I can't find any reference about how to set *_BINDANY option on Mac OS X
    //
    // It may result in `bind()` returns `EADDRNOTAVAIL`
    // https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/bind.2.html#//apple_ref/doc/man/2/bind

    let err = Error::new(ErrorKind::Other, "Mac OS X doesn't support UDP transparent proxy");
    Err(err)
}

pub fn set_socket_before_bind(_addr: &SocketAddr, _socket: &Socket) -> io::Result<()> {
    unimplemented!("Mac OS X doesn't support UDP transparent proxy");
}

pub fn recv_from_with_destination(_socket: &UdpSocket, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    unimplemented!("Mac OS X doesn't support UDP transparent proxy");
}
