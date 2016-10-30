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

//! UdpRelay implementation

use std::net::SocketAddr;
use std::mem;
use std::io;

use tokio_core::net::UdpSocket;

use futures::stream::Stream;
use futures::{Future, Poll, Async};

pub mod local;
// pub mod server;

/// The maximum UDP payload size (defined in the original shadowsocks Python)
///
/// *I cannot find any references about why clowwindy used this value as the maximum
/// Socks5 UDP ASSOCIATE packet size. The only thing I can find is
/// [here](http://support.microsoft.com/kb/822061/)*
pub const MAXIMUM_UDP_PAYLOAD_SIZE: usize = 65536;

/// Maximum associations to maintain
pub const MAXIMUM_ASSOCIATE_MAP_SIZE: usize = 65536;

/// UDP incoming stream
pub struct Incoming {
    socket: UdpSocket,
}

impl Stream for Incoming {
    type Item = (Vec<u8>, SocketAddr);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        if self.socket.poll_read().is_not_ready() {
            return Ok(Async::NotReady);
        }

        let mut buf = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        match self.socket.recv_from(&mut buf) {
            Ok((n, addr)) => Ok(Some((buf[..n].to_vec(), addr)).into()),
            Err(err) => Err(err),
        }
    }
}

/// Handle UDP connections as stream
pub fn udp_incoming(socket: UdpSocket) -> Incoming {
    Incoming { socket: socket }
}

/// Future for `send_to`
pub enum SendToUdpSocket<B: AsRef<[u8]>> {
    Pending {
        socket: UdpSocket,
        buf: B,
        target_addr: SocketAddr,
    },
    Empty,
}

impl<B: AsRef<[u8]>> Future for SendToUdpSocket<B> {
    type Item = (UdpSocket, B, usize);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let length = match self {
            &mut SendToUdpSocket::Empty => panic!("poll after SendToUdpSocket is finished"),
            &mut SendToUdpSocket::Pending { ref socket, ref buf, ref target_addr } => {
                if socket.poll_write().is_not_ready() {
                    return Ok(Async::NotReady);
                }

                try_nb!(socket.send_to(buf.as_ref(), target_addr))
            }
        };

        match mem::replace(self, SendToUdpSocket::Empty) {
            SendToUdpSocket::Pending { socket, buf, .. } => Ok((socket, buf, length).into()),
            SendToUdpSocket::Empty => unreachable!(),
        }
    }
}

/// Send data to UdpSocket
pub fn send_to<B: AsRef<[u8]>>(socket: UdpSocket, buf: B, target: SocketAddr) -> SendToUdpSocket<B> {
    SendToUdpSocket::Pending {
        socket: socket,
        buf: buf,
        target_addr: target,
    }
}