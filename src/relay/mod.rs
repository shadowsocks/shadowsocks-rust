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

//! Relay server in local and server side implementations.

use std::io::{self, Read, Write};
use std::net::SocketAddr;

pub use self::local::RelayLocal;
pub use self::server::RelayServer;

use ip::IpAddr;

mod tcprelay;
#[cfg(feature = "enable-udp")]
mod udprelay;
pub mod local;
pub mod server;
mod loadbalancing;
pub mod socks5;

pub const COROUTINE_STACK_SIZE: usize = 128 * 1024; // 128KB

pub trait Relay {
    fn run(&self);
}

fn copy<R: Read, W: Write>(r: &mut R, w: &mut W, prefix: &str) -> io::Result<u64> {
    let mut buf = [0u8; 4096];
    let mut written = 0;
    loop {
        let len = match r.read(&mut buf) {
            Ok(0) => {
                trace!("{}: EOF from reader", prefix);
                return Ok(written);
            }
            Ok(len) => len,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                trace!("{}: Error from reader {:?}", prefix, e);
                return Err(e);
            }
        };
        trace!("{}: Read {} bytes from reader", prefix, len);
        match w.write_all(&buf[..len]) {
            Ok(..) => {},
            Err(err) => {
                trace!("{}: Error from writer {:?}", prefix, err);
                return Err(err);
            }
        }
        trace!("{}: Write {} bytes to writer", prefix, len);
        written += len as u64;
    }
}

fn take_ip_addr(sockaddr: &SocketAddr) -> IpAddr {
    match sockaddr {
        &SocketAddr::V4(ref v4) => IpAddr::V4(*v4.ip()),
        &SocketAddr::V6(ref v6) => IpAddr::V6(*v6.ip()),
    }
}
