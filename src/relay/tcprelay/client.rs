//! TCP relay client implementation

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{self, Poll},
};

use log::trace;
use pin_project::pin_project;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};

use super::ProxyStream;
use crate::{
    config::ServerConfig,
    context::SharedContext,
    relay::socks5::{
        self,
        Address,
        Command,
        HandshakeRequest,
        HandshakeResponse,
        Reply,
        TcpRequestHeader,
        TcpResponseHeader,
    },
};

/// Socks5 proxy client
#[pin_project]
pub struct Socks5Client {
    #[pin]
    stream: TcpStream,
}

impl Socks5Client {
    /// Connects to `addr` via `proxy`
    pub async fn connect<A>(addr: A, proxy: &SocketAddr) -> io::Result<Socks5Client>
    where
        Address: From<A>,
    {
        let mut s = TcpStream::connect(proxy).await?;

        // 1. Handshake
        let hs = HandshakeRequest::new(vec![socks5::SOCKS5_AUTH_METHOD_NONE]);
        trace!("client connected, going to send handshake: {:?}", hs);

        hs.write_to(&mut s).await?;

        let hsp = HandshakeResponse::read_from(&mut s).await?;

        trace!("got handshake response: {:?}", hsp);
        assert_eq!(hsp.chosen_method, socks5::SOCKS5_AUTH_METHOD_NONE);

        // 2. Send request header
        let h = TcpRequestHeader::new(Command::TcpConnect, From::from(addr));
        trace!("going to connect, req: {:?}", h);
        h.write_to(&mut s).await?;

        let hp = TcpResponseHeader::read_from(&mut s).await?;

        trace!("got response: {:?}", hp);
        match hp.reply {
            Reply::Succeeded => (),
            r => {
                let err = io::Error::new(io::ErrorKind::Other, format!("{}", r));
                return Err(err);
            }
        }

        Ok(Socks5Client { stream: s })
    }

    /// UDP Associate `addr` via `proxy`
    pub async fn udp_associate<A>(addr: A, proxy: &SocketAddr) -> io::Result<(Socks5Client, Address)>
    where
        Address: From<A>,
    {
        let mut s = TcpStream::connect(proxy).await?;

        // 1. Handshake
        let hs = HandshakeRequest::new(vec![socks5::SOCKS5_AUTH_METHOD_NONE]);
        trace!("client connected, going to send handshake: {:?}", hs);

        hs.write_to(&mut s).await?;

        let hsp = HandshakeResponse::read_from(&mut s).await?;

        trace!("got handshake response: {:?}", hsp);
        assert_eq!(hsp.chosen_method, socks5::SOCKS5_AUTH_METHOD_NONE);

        // 2. Send request header
        let h = TcpRequestHeader::new(Command::UdpAssociate, From::from(addr));
        trace!("going to connect, req: {:?}", h);

        h.write_to(&mut s).await?;
        let hp = TcpResponseHeader::read_from(&mut s).await?;

        trace!("got response: {:?}", hp);
        match hp.reply {
            Reply::Succeeded => (),
            r => {
                let err = io::Error::new(io::ErrorKind::Other, format!("{}", r));
                return Err(err);
            }
        }

        Ok((Socks5Client { stream: s }, hp.address))
    }
}

impl AsyncRead for Socks5Client {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), io::Error>> {
        self.project().stream.poll_read(cx, buf)
    }
}

impl AsyncWrite for Socks5Client {
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        self.project().stream.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().stream.poll_shutdown(cx)
    }
}

/// Shadowsocks' TCP client
#[pin_project]
pub struct ServerClient {
    #[pin]
    stream: ProxyStream,
}

impl ServerClient {
    /// Connect to target address via shadowsocks' server
    pub async fn connect(context: SharedContext, addr: &Address, svr_cfg: &ServerConfig) -> io::Result<ServerClient> {
        let stream = ProxyStream::connect_proxied(context, svr_cfg, addr).await?;
        Ok(ServerClient { stream })
    }
}

impl AsyncRead for ServerClient {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), io::Error>> {
        self.project().stream.poll_read(cx, buf)
    }
}

impl AsyncWrite for ServerClient {
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        self.project().stream.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().stream.poll_shutdown(cx)
    }
}
