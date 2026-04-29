//! Standalone SOCKS5 TCP client.
//!
//! This is the self-contained client used by the local SOCKS server
//! (and integration tests / `ssurl`). It handles its own TCP dial and
//! exposes the resulting tunnel as an [`AsyncRead`] / [`AsyncWrite`]
//! object. For the chain-aware in-band negotiator used internally by
//! the outbound proxy chain see
//! [`crate::net::Socks5Negotiator`].

use std::{
    io,
    pin::Pin,
    task::{self, Poll},
};

use pin_project::pin_project;
use shadowsocks::relay::socks5::{Address, Command, Error as Socks5Error};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpStream, ToSocketAddrs},
};

use crate::net::{Socks5Auth, Socks5Negotiator};

/// SOCKS5 TCP proxy client.
#[pin_project]
pub struct Socks5TcpClient {
    #[pin]
    stream: TcpStream,
}

impl Socks5TcpClient {
    /// Connect to `target` via the SOCKS5 server at `proxy` (no auth).
    pub async fn connect<A, P>(target: A, proxy: P) -> Result<Self, Socks5Error>
    where
        A: Into<Address>,
        P: ToSocketAddrs,
    {
        Self::connect_with_auth(target, proxy, &Socks5Auth::None).await
    }

    /// Connect with explicit authentication.
    pub async fn connect_with_auth<A, P>(target: A, proxy: P, auth: &Socks5Auth) -> Result<Self, Socks5Error>
    where
        A: Into<Address>,
        P: ToSocketAddrs,
    {
        let mut stream = TcpStream::connect(proxy).await?;
        Socks5Negotiator::establish_tcp(&mut stream, target, auth).await?;
        Ok(Self { stream })
    }

    /// Issue `UDP ASSOCIATE` on a fresh TCP connection to `proxy`. Returns
    /// the TCP control client (must be kept alive for the lifetime of the
    /// UDP association) and the relay address advertised by the server.
    pub async fn udp_associate<A, P>(announce: A, proxy: P) -> Result<(Self, Address), Socks5Error>
    where
        A: Into<Address>,
        P: ToSocketAddrs,
    {
        Self::udp_associate_with_auth(announce, proxy, &Socks5Auth::None).await
    }

    /// `udp_associate` with explicit authentication.
    pub async fn udp_associate_with_auth<A, P>(
        announce: A,
        proxy: P,
        auth: &Socks5Auth,
    ) -> Result<(Self, Address), Socks5Error>
    where
        A: Into<Address>,
        P: ToSocketAddrs,
    {
        let mut stream = TcpStream::connect(proxy).await?;
        Socks5Negotiator::handshake(&mut stream, auth).await?;
        let resp = Socks5Negotiator::command(&mut stream, Command::UdpAssociate, announce.into()).await?;
        Ok((Self { stream }, resp.address))
    }
}

impl AsyncRead for Socks5TcpClient {
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.project().stream.poll_read(cx, buf)
    }
}

impl AsyncWrite for Socks5TcpClient {
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.project().stream.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.project().stream.poll_shutdown(cx)
    }
}
