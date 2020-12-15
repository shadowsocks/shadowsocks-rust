//! UDP socket wrappers

use std::{
    io,
    ops::{Deref, DerefMut},
};

use pin_project::pin_project;

use crate::{
    context::Context,
    relay::{socks5::Address, sys::create_outbound_udp_socket},
    ServerAddr,
};

use super::connect_opt::ConnectOpts;

/// Wrappers for outbound `UdpSocket`
#[pin_project]
pub struct UdpSocket(#[pin] tokio::net::UdpSocket);

impl UdpSocket {
    /// Connects to shadowsocks server
    pub async fn connect_server_with_opts(
        context: &Context,
        addr: &ServerAddr,
        opts: &ConnectOpts,
    ) -> io::Result<UdpSocket> {
        let socket = match *addr {
            ServerAddr::SocketAddr(ref remote_addr) => {
                let socket = create_outbound_udp_socket(remote_addr, opts).await?;
                socket.connect(remote_addr).await?;
                socket
            }
            ServerAddr::DomainName(ref dname, port) => {
                lookup_then!(&context, dname, port, |remote_addr| {
                    let s = create_outbound_udp_socket(&remote_addr, opts).await?;
                    s.connect(remote_addr).await.map(|_| s)
                })?
                .1
            }
        };

        Ok(UdpSocket(socket))
    }

    /// Connects to proxy target
    pub async fn connect_remote_with_opts(
        context: &Context,
        addr: &Address,
        opts: &ConnectOpts,
    ) -> io::Result<UdpSocket> {
        let socket = match *addr {
            Address::SocketAddress(ref remote_addr) => {
                let socket = create_outbound_udp_socket(remote_addr, opts).await?;
                socket.connect(remote_addr).await?;
                socket
            }
            Address::DomainNameAddress(ref dname, port) => {
                lookup_then!(&context, dname, port, |remote_addr| {
                    let s = create_outbound_udp_socket(&remote_addr, opts).await?;
                    s.connect(remote_addr).await.map(|_| s)
                })?
                .1
            }
        };

        Ok(UdpSocket(socket))
    }
}

impl Deref for UdpSocket {
    type Target = tokio::net::UdpSocket;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for UdpSocket {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<tokio::net::UdpSocket> for UdpSocket {
    fn from(s: tokio::net::UdpSocket) -> Self {
        UdpSocket(s)
    }
}

impl Into<tokio::net::UdpSocket> for UdpSocket {
    fn into(self) -> tokio::net::UdpSocket {
        self.0
    }
}
