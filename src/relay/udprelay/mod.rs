//! Relay for UDP implementation
//!
//! ## ShadowSocks UDP protocol
//!
//! SOCKS5 UDP Request
//! +----+------+------+----------+----------+----------+
//! |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//! +----+------+------+----------+----------+----------+
//! | 2  |  1   |  1   | Variable |    2     | Variable |
//! +----+------+------+----------+----------+----------+
//!
//! SOCKS5 UDP Response
//! +----+------+------+----------+----------+----------+
//! |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//! +----+------+------+----------+----------+----------+
//! | 2  |  1   |  1   | Variable |    2     | Variable |
//! +----+------+------+----------+----------+----------+
//!
//! shadowsocks UDP Request (before encrypted)
//! +------+----------+----------+----------+
//! | ATYP | DST.ADDR | DST.PORT |   DATA   |
//! +------+----------+----------+----------+
//! |  1   | Variable |    2     | Variable |
//! +------+----------+----------+----------+
//!
//! shadowsocks UDP Response (before encrypted)
//! +------+----------+----------+----------+
//! | ATYP | DST.ADDR | DST.PORT |   DATA   |
//! +------+----------+----------+----------+
//! |  1   | Variable |    2     | Variable |
//! +------+----------+----------+----------+
//!
//! shadowsocks UDP Request and Response (after encrypted)
//! +-------+--------------+
//! |   IV  |    PAYLOAD   |
//! +-------+--------------+
//! | Fixed |   Variable   |
//! +-------+--------------+

use std::io;
use std::mem;
use std::net::SocketAddr;
use std::rc::Rc;

use tokio_core::net::UdpSocket;

use futures::{Async, Future, Poll, Stream};

pub mod local;
pub mod server;

mod crypto_io;

/// The maximum UDP payload size (defined in the original shadowsocks Python)
///
/// *I cannot find any references about why clowwindy used this value as the maximum
/// Socks5 UDP ASSOCIATE packet size. The only thing I can find is
/// [here](http://support.microsoft.com/kb/822061/)*
pub const MAXIMUM_UDP_PAYLOAD_SIZE: usize = 65536;

/// UDP `recv_from` stream
pub struct PacketStream {
    udp: Rc<UdpSocket>,
    buf: [u8; MAXIMUM_UDP_PAYLOAD_SIZE],
}

impl PacketStream {
    /// Creates a new `PacketStream`
    pub fn new(udp: Rc<UdpSocket>) -> PacketStream {
        PacketStream { udp: udp,
                       buf: [0u8; MAXIMUM_UDP_PAYLOAD_SIZE], }
    }
}

impl Stream for PacketStream {
    type Item = (Vec<u8>, SocketAddr);
    type Error = io::Error;
    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let (n, addr) = try_nb!(self.udp.recv_from(&mut self.buf));
        Ok(Async::Ready(Some((self.buf[..n].to_vec(), addr))))
    }
}

enum SendDgramStat<B: AsRef<[u8]>> {
    Pending {
        udp: Rc<UdpSocket>,
        buf: B,
        addr: SocketAddr,
    },
    Empty,
}

/// Send datagram with `Rc<UdpSocket>`
pub struct SendDgramRc<B: AsRef<[u8]>> {
    stat: SendDgramStat<B>,
}

impl<B: AsRef<[u8]>> SendDgramRc<B> {
    pub fn new(udp: Rc<UdpSocket>, buf: B, addr: SocketAddr) -> SendDgramRc<B> {
        SendDgramRc { stat: SendDgramStat::Pending { udp: udp,
                                                     buf: buf,
                                                     addr: addr, }, }
    }
}

impl<B: AsRef<[u8]>> Future for SendDgramRc<B> {
    type Item = (Rc<UdpSocket>, usize, B);
    type Error = io::Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let n = match self.stat {
            SendDgramStat::Pending { ref udp,
                                     ref buf,
                                     ref addr, } => try_nb!(udp.send_to(buf.as_ref(), addr)),
            SendDgramStat::Empty => unreachable!(),
        };

        match mem::replace(&mut self.stat, SendDgramStat::Empty) {
            SendDgramStat::Pending { udp, buf, .. } => Ok(Async::Ready((udp, n, buf))),
            SendDgramStat::Empty => unreachable!(),
        }
    }
}
