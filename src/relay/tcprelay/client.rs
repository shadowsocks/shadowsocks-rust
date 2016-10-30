// The MIT License (MIT)

// Copyright (c) 2014 Y. T. CHUNG <zonyitoo@gmail.com>

// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

//! TCP relay client implementation

use std::io::{self, Read, Write};
use std::net::SocketAddr;

use tokio_core::reactor::Handle;
use tokio_core::net::TcpStream;

use futures::{self, Future};

use relay::socks5::{self, HandshakeRequest, HandshakeResponse, Address, TcpRequestHeader, TcpResponseHeader, Command,
                    Reply};
use relay::{BoxIoFuture, boxed_future};

/// Socks5 proxy client
pub struct Socks5Client {
    stream: TcpStream,
}

impl Socks5Client {
    /// Connects to `addr` via `proxy`
    pub fn connect<A>(addr: A, proxy: SocketAddr, handle: Handle) -> BoxIoFuture<Socks5Client>
        where Address: From<A>,
              A: 'static
    {
        let fut = futures::lazy(move || TcpStream::connect(&proxy, &handle))
            .and_then(move |s| {
                // 1. Handshake
                let hs = HandshakeRequest::new(vec![socks5::SOCKS5_AUTH_METHOD_NONE]);
                trace!("Client connected, going to send handshake: {:?}", hs);

                hs.write_to(s)
                    .and_then(|s| HandshakeResponse::read_from(s))
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