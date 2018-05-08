//! TCP relay client implementation

use std::io::{self, Read, Write};
use std::net::SocketAddr;

use tokio::net::TcpStream;
use tokio_io::io::flush;
use tokio_io::{AsyncRead, AsyncWrite, IoFuture};

use futures::{self, Async, Future, Poll};

use relay::boxed_future;
use relay::socks5::{self, Address, Command, HandshakeRequest, HandshakeResponse, Reply, TcpRequestHeader,
                    TcpResponseHeader};

/// Socks5 proxy client
pub struct Socks5Client {
    stream: TcpStream,
}

impl Socks5Client {
    /// Connects to `addr` via `proxy`
    pub fn connect<A>(addr: A, proxy: SocketAddr) -> IoFuture<Socks5Client>
        where Address: From<A>,
              A: Send + 'static
    {
        let fut = futures::lazy(move || TcpStream::connect(&proxy))
            .and_then(move |s| {
                // 1. Handshake
                let hs = HandshakeRequest::new(vec![socks5::SOCKS5_AUTH_METHOD_NONE]);
                trace!("Client connected, going to send handshake: {:?}", hs);

                hs.write_to(s)
                  .and_then(flush)
                  .and_then(HandshakeResponse::read_from)
                  .and_then(|(s, rsp)| {
                                trace!("Got handshake response: {:?}", rsp);
                                assert_eq!(rsp.chosen_method, socks5::SOCKS5_AUTH_METHOD_NONE);
                                Ok(s)
                            })
            })
            .and_then(move |s| {
                // 2. Send request header
                let h = TcpRequestHeader::new(Command::TcpConnect, From::from(addr));
                trace!("Going to connect, req: {:?}", h);
                h.write_to(s)
                 .and_then(flush)
                 .and_then(|s| TcpResponseHeader::read_from(s).map_err(From::from))
                 .and_then(|(s, rsp)| {
                    trace!("Got response: {:?}", rsp);
                    match rsp.reply {
                        Reply::Succeeded => Ok(s),
                        r => {
                            let err = io::Error::new(io::ErrorKind::Other, format!("{}", r));
                            Err(err)
                        }
                    }
                })
            })
            .map(|s| Socks5Client { stream: s });

        boxed_future(fut)
    }

    /// UDP Associate `addr` via `proxy`
    pub fn udp_associate<A>(addr: A, proxy: SocketAddr) -> IoFuture<(Socks5Client, Address)>
        where Address: From<A>,
              A: Send + 'static
    {
        let fut = futures::lazy(move || TcpStream::connect(&proxy))
            .and_then(move |s| {
                // 1. Handshake
                let hs = HandshakeRequest::new(vec![socks5::SOCKS5_AUTH_METHOD_NONE]);
                trace!("Client connected, going to send handshake: {:?}", hs);

                hs.write_to(s)
                  .and_then(flush)
                  .and_then(HandshakeResponse::read_from)
                  .and_then(|(s, rsp)| {
                                trace!("Got handshake response: {:?}", rsp);
                                assert_eq!(rsp.chosen_method, socks5::SOCKS5_AUTH_METHOD_NONE);
                                Ok(s)
                            })
            })
            .and_then(move |s| {
                // 2. Send request header
                let h = TcpRequestHeader::new(Command::UdpAssociate, From::from(addr));
                trace!("Going to connect, req: {:?}", h);
                h.write_to(s)
                 .and_then(flush)
                 .and_then(|s| TcpResponseHeader::read_from(s).map_err(From::from))
                 .and_then(|(s, rsp)| {
                    trace!("Got response: {:?}", rsp);
                    match rsp.reply {
                        Reply::Succeeded => Ok((s, rsp.address)),
                        r => {
                            let err = io::Error::new(io::ErrorKind::Other, format!("{}", r));
                            Err(err)
                        }
                    }
                })
            })
            .map(|(s, a)| (Socks5Client { stream: s }, a));

        boxed_future(fut)
    }
}

impl Read for Socks5Client {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

impl Write for Socks5Client {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl AsyncRead for Socks5Client {}
impl AsyncWrite for Socks5Client {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        // FIXME: Finalize the internal cipher
        Ok(Async::Ready(()))
    }
}
