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
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::mem;
use std::str;
use std::fmt;

use hyper::uri::RequestUri;
use hyper::header::{Header, HeaderFormat, Headers, ContentLength};
use hyper::header::{Connection, ConnectionOption};
use hyper::status::StatusCode;
use hyper::version::HttpVersion;
use hyper::method::Method;
use hyper;

use httparse::{self, Request};

use url::Host;

use ip::IpAddr;

use futures::{self, Future, Poll};

use tokio_core::io::{write_all, flush};

use relay::socks5::Address;
use relay::{BoxIoFuture, boxed_future};
use super::stream::EncryptedWriter;

#[derive(Debug)]
pub struct HttpRequest {
    pub version: HttpVersion,
    pub method: Method,
    pub request_uri: RequestUri,
    pub headers: Headers,
}

impl HttpRequest {
    pub fn from_raw<'headers, 'buf: 'headers>(req: &Request<'headers, 'buf>,
                                              headers: &'headers [httparse::Header])
                                              -> hyper::Result<HttpRequest> {
        Ok(HttpRequest {
            version: if req.version.unwrap() == 1 {
                HttpVersion::Http11
            } else {
                HttpVersion::Http10
            },
            method: try!(req.method.unwrap().parse::<Method>()),
            request_uri: try!(req.path.unwrap().parse::<RequestUri>()),
            headers: try!(Headers::from_raw(headers)),
        })
    }

    pub fn clear_request_uri_host(&mut self) {
        let ptr = &mut self.request_uri as *mut RequestUri;
        match &mut self.request_uri {
            &mut RequestUri::AbsoluteUri(ref url) => {
                let mut abs = String::new();
                abs += url.path();
                if let Some(query) = url.query() {
                    abs += "?";
                    abs += query;
                }

                if let Some(frag) = url.fragment() {
                    abs += "#";
                    abs += frag;
                }

                // Force replace
                let unsafe_ref = unsafe { &mut *ptr };
                ::std::mem::replace(unsafe_ref, RequestUri::AbsolutePath(abs));
            }
            _ => {}
        }
    }

    /// Writes request into an EncryptedWriter
    pub fn write_to_encrypted<W>(self, w: EncryptedWriter<W>) -> BoxIoFuture<EncryptedWriter<W>>
        where W: Write + 'static
    {
        let fut = futures::lazy(move || {
                let mut w = Vec::new();
                try!(write!(w,
                            "{} {} {}\r\n",
                            self.method,
                            self.request_uri,
                            self.version));

                for header in self.headers.iter() {
                    if !header.name().is_empty() {
                        try!(write!(w, "{}: {}\r\n", header.name(), header.value_string()));
                    }
                }

                try!(write!(w, "\r\n"));

                Ok(w)
            })
            .and_then(|buf| w.write_all_encrypted(buf))
            .map(|(w, _)| w);

        Box::new(fut)
    }

    /// Get Socks5 address from URI
    #[inline]
    pub fn get_address(&self) -> Result<Address, StatusCode> {
        get_address(&self.request_uri)
    }
}

fn get_address(uri: &RequestUri) -> Result<Address, StatusCode> {
    match uri {
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
        &RequestUri::AbsoluteUri(ref uri) => {
            if !uri.has_host() {
                error!("URI does not have Host: {:?}", uri);
                return Err(StatusCode::BadRequest);
            }

            let port = uri.port_or_known_default().unwrap_or(80);

            let addr = match uri.host().unwrap() {
                Host::Domain(dom) => Address::DomainNameAddress(dom.to_owned(), port),
                Host::Ipv4(v4) => Address::SocketAddress(SocketAddr::V4(SocketAddrV4::new(v4, port))),
                Host::Ipv6(v6) => Address::SocketAddress(SocketAddr::V6(SocketAddrV6::new(v6, port, 0, 0))),
            };

            Ok(addr)
        }
        u => {
            error!("Invalid Uri {:?}", u);
            Err(StatusCode::BadRequest)
        }
    }
}

pub fn write_response<W>(w: W, version: HttpVersion, status: StatusCode) -> BoxIoFuture<W>
    where W: Write + 'static
{
    let buf = format!("{} {}\r\n\r\n", version, status);
    Box::new(write_all(w, buf.into_bytes()).map(|(w, _)| w))
}

/// X-Forward-For header
#[derive(Debug, Clone)]
pub struct XForwardFor(pub Vec<IpAddr>);

impl Header for XForwardFor {
    fn header_name() -> &'static str {
        "X-Forward-For"
    }

    fn parse_header(raw: &[Vec<u8>]) -> hyper::Result<XForwardFor> {
        let mut ips = Vec::new();
        for raw_h in raw.iter() {
            let xfor = try!(str::from_utf8(&raw_h[..]));
            for xfor_str in xfor.split(',') {
                let trimmed = xfor_str.trim();
                if trimmed.is_empty() {
                    // Ignore empty string
                    continue;
                }
                match trimmed.parse::<IpAddr>() {
                    Ok(i) => ips.push(i),
                    Err(..) => return Err(hyper::Error::Header),
                }
            }
        }

        Ok(XForwardFor(ips))
    }
}

impl HeaderFormat for XForwardFor {
    fn fmt_header(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut first = true;
        for ip in &self.0 {
            if first {
                first = false;
            } else {
                try!(write!(f, ", "));
            }

            try!(write!(f, "{}", ip));
        }

        Ok(())
    }
}

/// X-Real-IP header
#[derive(Debug, Clone)]
pub struct XRealIp(pub IpAddr);

impl Header for XRealIp {
    fn header_name() -> &'static str {
        "X-Real-IP"
    }

    fn parse_header(raw: &[Vec<u8>]) -> hyper::Result<XRealIp> {
        let mut ip = None;
        for raw_ip in raw.iter() {
            let x_ip = try!(str::from_utf8(&raw_ip[..]));
            match x_ip.trim().parse::<IpAddr>() {
                Ok(i) => {
                    if let Some(prev_ip) = ip.take() {
                        if prev_ip != i {
                            return Err(hyper::Error::Header);
                        }
                    }

                    ip = Some(i);
                }
                Err(..) => return Err(hyper::Error::Header),
            }
        }

        match ip {
            Some(ip) => Ok(XRealIp(ip)),
            None => Err(hyper::Error::Header),
        }
    }
}

impl HeaderFormat for XRealIp {
    #[inline]
    fn fmt_header(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Future for reading HttpRequest
pub enum HttpRequestFut<R>
    where R: Read
{
    Pending { r: R, buf: Vec<u8> },
    Empty,
}

impl<R> HttpRequestFut<R>
    where R: Read
{
    pub fn new(r: R) -> HttpRequestFut<R> {
        HttpRequestFut::with_buf(r, Vec::new())
    }

    pub fn with_buf(r: R, buf: Vec<u8>) -> HttpRequestFut<R> {
        HttpRequestFut::Pending { r: r, buf: buf }
    }
}

impl<R> Future for HttpRequestFut<R>
    where R: Read
{
    type Item = (R, HttpRequest, Vec<u8>);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let mut lbuf = [0u8; 4096];
        let (req, len) = match self {
            &mut HttpRequestFut::Pending { ref mut r, ref mut buf } => {
                // FIXME: Compiler force me to do this!
                let http_req: Option<HttpRequest>;
                let total_len: usize;
                loop {
                    let n = try_nb!(r.read(&mut lbuf));
                    buf.extend_from_slice(&lbuf[..n]);

                    // Maximum 128 headers
                    let mut headers = [httparse::EMPTY_HEADER; 128];
                    let headers_ptr = &headers as *const _;
                    let mut req = Request::new(&mut headers);
                    match req.parse(&mut buf[..]) {
                        Ok(httparse::Status::Partial) => {
                            if n == 0 {
                                // Already EOF!
                                let err = io::Error::new(io::ErrorKind::UnexpectedEof, "Unexpected Eof");
                                return Err(err);
                            }
                        }
                        Ok(httparse::Status::Complete(len)) => {
                            total_len = len;

                            // Make borrow checker happy
                            let headers_ref = unsafe { &*headers_ptr };
                            let hreq = match HttpRequest::from_raw(&req, headers_ref) {
                                Ok(r) => r,
                                Err(err) => {
                                    error!("HttpRequest::from_raw: {}", err);
                                    let err = io::Error::new(io::ErrorKind::Other, "Hyper error");
                                    return Err(err);
                                }
                            };
                            http_req = Some(hreq);
                            break;
                        }
                        Err(err) => {
                            error!("Request parse: {:?}", err);
                            let err = io::Error::new(io::ErrorKind::Other, "Hyper error");
                            return Err(err);
                        }
                    }
                }

                (http_req.unwrap(), total_len)
            }
            &mut HttpRequestFut::Empty => panic!("poll a HttpRequestFut after it's done"),
        };

        match mem::replace(self, HttpRequestFut::Empty) {
            HttpRequestFut::Pending { r, buf } => Ok((r, req, buf[len..].to_vec()).into()),
            HttpRequestFut::Empty => unreachable!(),
        }
    }
}

fn socket_to_ip(addr: &SocketAddr) -> IpAddr {
    match *addr {
        SocketAddr::V4(ref v4) => IpAddr::V4(v4.ip().clone()),
        SocketAddr::V6(ref v6) => IpAddr::V6(v6.ip().clone()),
    }
}

/// Proxy this HTTP Request to writer
pub fn proxy_request_encrypted<R, W>((r, w): (R, EncryptedWriter<W>),
                                     client_addr: Option<&SocketAddr>,
                                     mut req: HttpRequest,
                                     mut remains: Vec<u8>)
                                     -> BoxIoFuture<(R, EncryptedWriter<W>, Vec<u8>)>
    where R: Read + 'static,
          W: Write + 'static
{
    let content_length = req.headers.get::<ContentLength>().unwrap_or(&ContentLength(0)).0 as usize;

    if let Some(client_addr) = client_addr {
        let client_ip = socket_to_ip(client_addr);

        // Set proxy IP info
        let xf = if let Some(fw) = req.headers.get_mut::<XForwardFor>() {
            let mut flst = fw.0.clone();
            flst.push(client_ip.clone());
            flst
        } else {
            vec![client_ip.clone()]
        };
        req.headers.set(XForwardFor(xf));

        // Set real ip
        req.headers.set(XRealIp(client_ip));
    }

    // Clears host, which only for proxy
    req.clear_request_uri_host();

    let fut = req.write_to_encrypted(w)
        .and_then(|w| flush(w))
        .and_then(move |w| {
            if content_length == 0 {
                boxed_future(futures::finished((r, w, remains)))
            } else if content_length <= remains.len() {
                let after_that = remains.split_off(content_length);
                boxed_future(w.write_all_encrypted(remains).map(|(w, _)| (r, w, after_that)))
            } else {
                let missing_bytes = content_length - remains.len();
                let fut = w.write_all_encrypted(remains)
                    .and_then(move |(w, _)| {
                        super::copy_exact_encrypted(r, w, missing_bytes).map(|(r, w)| (r, w, vec![]))
                    });
                boxed_future(fut)
            }
        });
    Box::new(fut)
}

/// Check `Connection` header to determine whether we should keep alive
pub fn should_keep_alive(req: &HttpRequest) -> bool {
    let default_keep_alive = req.version >= HttpVersion::Http11;
    match req.headers.get::<Connection>() {
        Some(conn) => {
            for opt in conn.iter() {
                if let &ConnectionOption::KeepAlive = opt {
                    return true;
                }
            }

            default_keep_alive
        }
        None => default_keep_alive,
    }
}