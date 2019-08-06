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

use std::{
    io, mem,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use tokio::net::UdpSocket;

use futures::{try_ready, Async, Future, Poll, Stream};

pub mod dns;
pub mod local;
pub mod server;

mod crypto_io;

/// The maximum UDP payload size (defined in the original shadowsocks Python)
///
/// *I cannot find any references about why clowwindy used this value as the maximum
/// Socks5 UDP ASSOCIATE packet size. The only thing I can find is
/// [here](http://support.microsoft.com/kb/822061/)*
pub const MAXIMUM_UDP_PAYLOAD_SIZE: usize = 65536;

type SharedUdpSocket = Arc<Mutex<UdpSocket>>;

/// UDP `recv_from` stream
pub struct PacketStream {
    udp: SharedUdpSocket,
    buf: [u8; MAXIMUM_UDP_PAYLOAD_SIZE],
}

impl PacketStream {
    /// Creates a new `PacketStream`
    pub fn new(udp: SharedUdpSocket) -> PacketStream {
        PacketStream {
            udp,
            buf: [0u8; MAXIMUM_UDP_PAYLOAD_SIZE],
        }
    }
}

impl Stream for PacketStream {
    type Error = io::Error;
    type Item = (Vec<u8>, SocketAddr);

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let (n, addr) = try_ready!(self.udp.lock().unwrap().poll_recv_from(&mut self.buf));
        Ok(Async::Ready(Some((self.buf[..n].to_vec(), addr))))
    }
}

enum SendDgramStat<B: AsRef<[u8]>> {
    Pending {
        udp: SharedUdpSocket,
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
    pub fn new(udp: SharedUdpSocket, buf: B, addr: SocketAddr) -> SendDgramRc<B> {
        SendDgramRc {
            stat: SendDgramStat::Pending { udp, buf, addr },
        }
    }
}

impl<B: AsRef<[u8]>> Future for SendDgramRc<B> {
    type Error = io::Error;
    type Item = (SharedUdpSocket, usize, B);

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let n = match self.stat {
            SendDgramStat::Pending {
                ref udp,
                ref buf,
                ref addr,
            } => try_ready!(udp.lock().unwrap().poll_send_to(buf.as_ref(), addr)),
            SendDgramStat::Empty => unreachable!(),
        };

        match mem::replace(&mut self.stat, SendDgramStat::Empty) {
            SendDgramStat::Pending { udp, buf, .. } => Ok(Async::Ready((udp, n, buf))),
            SendDgramStat::Empty => unreachable!(),
        }
    }
}
