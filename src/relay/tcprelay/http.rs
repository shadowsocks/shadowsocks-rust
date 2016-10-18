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

/// Http Proxy

use std::io::{self, Read, Write};
use std::net::{SocketAddr, Shutdown};
use std::time::Duration;

use coio::net::TcpStream;

use hyper::net::NetworkStream;
use hyper::server::request::Request;
use hyper::server::response::Response;
use hyper::method::Method;
use hyper::uri::RequestUri;
use hyper::buffer::BufReader;
use hyper::header::Headers;
use hyper::status::StatusCode;

use relay::socks5::Address;

#[derive(Debug)]
pub struct HttpStream(pub TcpStream);

impl Read for HttpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for HttpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl NetworkStream for HttpStream {
    fn peer_addr(&mut self) -> io::Result<SocketAddr> {
        self.0.peer_addr()
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.0.set_read_timeout(dur)
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.0.set_write_timeout(dur)
    }

    fn close(&mut self, how: Shutdown) -> io::Result<()> {
        self.0.shutdown(how)
    }
}

fn do_handshake(stream: &mut HttpStream, addr: SocketAddr) -> Result<Address, StatusCode> {
    let mut reader = BufReader::new(stream as &mut NetworkStream);
    let request = match Request::new(&mut reader, addr) {
        Ok(r) => r,
        Err(err) => {
            error!("Failed to create Request: {:?}", err);
            return Err(StatusCode::BadRequest);
        }
    };

    match request.method {
        Method::Connect => {}
        _ => {
            error!("Does not support {:?}", request.method);
            return Err(StatusCode::MethodNotAllowed);
        }
    }

    match &request.uri {
        &RequestUri::Authority(ref s) => {
            match s.parse::<SocketAddr>() {
                Ok(addr) => Ok(Address::SocketAddress(addr)),
                Err(_) => {
                    let mut sp = s.splitn(2, ':');
                    match (sp.next(), sp.next()) {
                        (Some(host), Some(port)) => {
                            let port = match port.parse::<u16>() {
                                Ok(port) => port,
                                Err(err) => {
                                    error!("Failed to parse Url, {}", err);
                                    return Err(StatusCode::BadRequest);
                                }
                            };

                            Ok(Address::DomainNameAddress(host.to_owned(), port))
                        }
                        (host, port) => {
                            error!("Failed to parse Url, {:?}:{:?}", host, port);
                            return Err(StatusCode::BadRequest);
                        }
                    }
                }
            }
        }
        u => {
            error!("Invalid Uri {:?}", u);
            Err(StatusCode::BadRequest)
        }
    }
}

pub fn handshake(stream: &mut HttpStream, addr: SocketAddr) -> io::Result<Address> {
    match do_handshake(stream, addr) {
        Ok(r) => {
            stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .map(|_| r)
        }
        Err(status) => {
            let mut headers = Headers::new();
            let mut resp = Response::new(stream, &mut headers);
            *resp.status_mut() = status;
            try!(resp.start().and_then(|r| r.end()));

            let err = io::Error::new(io::ErrorKind::Other, "Handshake error");
            Err(err)
        }
    }

}
