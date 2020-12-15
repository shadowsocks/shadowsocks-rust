use std::{io, net::SocketAddr};

use async_trait::async_trait;

use crate::{config::RedirType, local::redir::redir_ext::UdpSocketRedirExt};

pub struct UdpRedirSocket;

impl UdpRedirSocket {
    /// Create a new UDP socket binded to `addr`
    ///
    /// This will allow binding to `addr` that is not in local host
    pub fn bind(_ty: RedirType, _addr: SocketAddr) -> io::Result<UdpRedirSocket> {
        unimplemented!("UDP transparent proxy is not supported on macOS, iOS, ...")
    }

    /// Send data to the socket to the given target address
    pub async fn send_to(&mut self, _buf: &[u8], _target: SocketAddr) -> io::Result<usize> {
        unimplemented!("UDP transparent proxy is not supported on macOS, iOS, ...")
    }

    /// Returns the local address that this socket is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        unimplemented!("UDP transparent proxy is not supported on macOS, iOS, ...")
    }
}

#[async_trait]
impl UdpSocketRedirExt for UdpRedirSocket {
    async fn recv_from_redir(&mut self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr, SocketAddr)> {
        unimplemented!("UDP transparent proxy is not supported on macOS, iOS, ...")
    }
}
