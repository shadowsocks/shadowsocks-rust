//! Utility functions

use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use futures::ready;
use log::trace;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpSocket, TcpStream},
};

use crate::crypto::v1::{CipherCategory, CipherKind};

/// Connecting to a specific target with TCP protocol
///
/// Optionally we can bind to a local address for connecting
pub async fn connect_tcp_stream(addr: &SocketAddr, outbound_addr: &Option<SocketAddr>) -> io::Result<TcpStream> {
    match *outbound_addr {
        None => {
            trace!("connecting {}", addr);

            // Connect with tokio's default API directly
            TcpStream::connect(addr).await
        }
        Some(ref bind_addr) => {
            // Create TcpStream manually from socket
            // These functions may not behave exactly the same as tokio's TcpStream::connect

            trace!("connecting {} from {}", addr, bind_addr);

            let socket = match *addr {
                SocketAddr::V4(..) => TcpSocket::new_v4()?,
                SocketAddr::V6(..) => TcpSocket::new_v6()?,
            };

            // Bind to local outbound address
            //
            // Common failure: EADDRINUSE
            socket.bind(*bind_addr)?;

            // Connect to the target
            //
            // FIXME: This function is not documented as it may be deleted in the future
            //
            // mio 0.6.x (tokio 0.2.x is depending on it) will set stream into non-block mode
            // unix: https://github.com/tokio-rs/mio/blob/v0.6.x/src/sys/unix/tcp.rs#L28
            // windows: https://github.com/tokio-rs/mio/blob/v0.6.x/src/sys/windows/tcp.rs#L118
            //
            // We have to let tokio calls connect for us. Because we don't have a chance to wait until the socket is actually connected
            socket.connect(*addr).await
        }
    }
}

pub struct ShadowTunnelCopy<'a, R: ?Sized, W: ?Sized> {
    reader: &'a mut R,
    read_done: bool,
    writer: &'a mut W,
    pos: usize,
    cap: usize,
    amt: u64,
    buf: Box<[u8]>,
}

impl<R, W> Future for ShadowTunnelCopy<'_, R, W>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<u64>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        loop {
            // If our buffer is empty, then we need to read some data to
            // continue.
            if self.pos == self.cap && !self.read_done {
                let me = &mut *self;
                let mut buf = ReadBuf::new(&mut me.buf);
                ready!(Pin::new(&mut *me.reader).poll_read(cx, &mut buf))?;
                let n = buf.filled().len();
                if n == 0 {
                    self.read_done = true;
                } else {
                    self.pos = 0;
                    self.cap = n;
                }
            }

            // If our buffer has some data, let's write it out!
            while self.pos < self.cap {
                let me = &mut *self;
                let i = ready!(Pin::new(&mut *me.writer).poll_write(cx, &me.buf[me.pos..me.cap]))?;
                if i == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero byte into writer",
                    )));
                } else {
                    self.pos += i;
                    self.amt += i as u64;
                }
            }

            // If we've written all the data and we've seen EOF, flush out the
            // data and finish the transfer.
            if self.pos == self.cap && self.read_done {
                let me = &mut *self;
                ready!(Pin::new(&mut *me.writer).poll_flush(cx))?;
                return Poll::Ready(Ok(self.amt));
            }
        }
    }
}

pub async fn shadow_tunnel_copy<'a, R, W>(method: CipherKind, reader: &'a mut R, writer: &'a mut W) -> io::Result<u64>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    let buffer_length = match method.category() {
        CipherCategory::Stream | CipherCategory::None => {
            // Stream cipher uses 16K buffer
            1 << 14
        }
        CipherCategory::Aead => {
            // AEAD cipher have a maximum packet size 0x3FFF
            // Reserves some space for TAGS and length for AEAD
            2 + method.tag_len() + super::aead::MAX_PACKET_SIZE + method.tag_len()
        }
    };

    let buf = vec![0u8; buffer_length].into_boxed_slice();

    ShadowTunnelCopy {
        reader,
        read_done: false,
        writer,
        amt: 0,
        pos: 0,
        cap: 0,
        buf,
    }
    .await
}
