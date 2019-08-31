//! TCP relay client implementation

use std::{
    io::{self, Write},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use log::trace;
use tokio::{
    net::{
        tcp::split::{TcpStreamReadHalf, TcpStreamWriteHalf},
        TcpStream,
    },
    prelude::*,
};

use crate::relay::socks5::{
    self,
    Address,
    Command,
    HandshakeRequest,
    HandshakeResponse,
    Reply,
    TcpRequestHeader,
    TcpResponseHeader,
};

use crate::{config::ServerConfig, context::SharedContext};

/// Socks5 proxy client
pub struct Socks5Client {
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
        trace!("Client connected, going to send handshake: {:?}", hs);

        hs.write_to(&mut s).await?;
        s.flush().await?;

        let hsp = HandshakeResponse::read_from(&mut s).await?;

        trace!("Got handshake response: {:?}", hsp);
        assert_eq!(hsp.chosen_method, socks5::SOCKS5_AUTH_METHOD_NONE);

        // 2. Send request header
        let h = TcpRequestHeader::new(Command::TcpConnect, From::from(addr));
        trace!("Going to connect, req: {:?}", h);

        h.write_to(&mut s).await?;
        s.flush().await?;
        let hp = TcpResponseHeader::read_from(&mut s).await?;

        trace!("Got response: {:?}", hp);
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
        trace!("Client connected, going to send handshake: {:?}", hs);

        hs.write_to(&mut s).await?;
        s.flush().await?;

        let hsp = HandshakeResponse::read_from(&mut s).await?;

        trace!("Got handshake response: {:?}", hsp);
        assert_eq!(hsp.chosen_method, socks5::SOCKS5_AUTH_METHOD_NONE);

        // 2. Send request header
        let h = TcpRequestHeader::new(Command::UdpAssociate, From::from(addr));
        trace!("Going to connect, req: {:?}", h);

        h.write_to(&mut s).await?;
        s.flush().await?;
        let hp = TcpResponseHeader::read_from(&mut s).await?;

        trace!("Got response: {:?}", hp);
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
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context, buf: &mut [u8]) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Socks5Client {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

pub(crate) struct ServerClient {
    pub r: super::DecryptedHalf<TcpStreamReadHalf>,
    pub w: super::EncryptedHalf<TcpStreamWriteHalf>,
}

impl ServerClient {
    pub(crate) async fn connect(
        context: SharedContext,
        addr: &Address,
        svr_cfg: Arc<ServerConfig>,
    ) -> io::Result<ServerClient> {
        let stream = super::connect_proxy_server(context, svr_cfg.clone()).await?;
        let (r, w) = super::proxy_server_handshake(stream, svr_cfg, addr).await?;

        Ok(ServerClient { r, w })
    }
}
