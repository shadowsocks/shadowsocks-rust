//! A TCP stream for communicating with shadowsocks' proxy client

use std::{
    io,
    pin::Pin,
    task::{self, Poll},
};

use bytes::BytesMut;
use futures::ready;
use pin_project::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    context::SharedContext,
    crypto::CipherKind,
    relay::{
        socks5::Address,
        tcprelay::{
            crypto_io::{CryptoRead, CryptoStream, CryptoWrite},
            proxy_stream::protocol::TcpRequestHeader,
        },
    },
};

enum ProxyServerStreamWriteState {
    #[cfg(feature = "aead-cipher-2022")]
    PrepareHeader(Option<std::task::Waker>),
    #[cfg(feature = "aead-cipher-2022")]
    WriteHeader(BytesMut, usize),
    Established,
}

/// A stream for communicating with shadowsocks' proxy client
#[pin_project]
pub struct ProxyServerStream<S> {
    #[pin]
    stream: CryptoStream<S>,
    context: SharedContext,
    writer_state: ProxyServerStreamWriteState,
}

impl<S> ProxyServerStream<S> {
    pub(crate) fn from_stream(
        context: SharedContext,
        stream: S,
        method: CipherKind,
        key: &[u8],
    ) -> ProxyServerStream<S> {
        #[cfg(feature = "aead-cipher-2022")]
        let writer_state = if method.is_aead_2022() {
            ProxyServerStreamWriteState::PrepareHeader(None)
        } else {
            ProxyServerStreamWriteState::Established
        };

        #[cfg(not(feature = "aead-cipher-2022"))]
        let writer_state = ProxyServerStreamWriteState::Established;

        ProxyServerStream {
            stream: CryptoStream::from_stream(&context, stream, method, key),
            context,
            writer_state,
        }
    }

    /// Get reference of the internal stream
    pub fn get_ref(&self) -> &S {
        self.stream.get_ref()
    }

    /// Get mutable reference of the internal stream
    pub fn get_mut(&mut self) -> &mut S {
        self.stream.get_mut()
    }

    /// Consumes the object and return the internal stream
    pub fn into_inner(self) -> S {
        self.stream.into_inner()
    }
}

impl<S> ProxyServerStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Handshaking. Getting the destination address from client
    ///
    /// This method should be called only once after accepted.
    pub async fn handshake(&mut self) -> io::Result<Address> {
        let header = TcpRequestHeader::read_from(self.stream.method(), self).await?;
        // TODO: Check header is not in a standalone AEAD package
        Ok(header.addr())
    }
}

impl<S> AsyncRead for ProxyServerStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.project();
        ready!(this.stream.poll_read_decrypted(cx, this.context, buf))?;

        // Wakeup writer task because we have already received the salt
        #[cfg(feature = "aead-cipher-2022")]
        if let ProxyServerStreamWriteState::PrepareHeader(ref mut waker) = this.writer_state {
            if let Some(waker) = waker.take() {
                waker.wake();
            }
        }

        Ok(()).into()
    }
}

impl<S> AsyncWrite for ProxyServerStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        let mut this = self.project();

        loop {
            match *this.writer_state {
                ProxyServerStreamWriteState::Established => {
                    return this.stream.poll_write_encrypted(cx, buf);
                }
                #[cfg(feature = "aead-cipher-2022")]
                ProxyServerStreamWriteState::PrepareHeader(ref mut waker) => {
                    match this.stream.received_nonce() {
                        None => {
                            // Reader didn't receive the salt from client yet.
                            if let Some(waker) = waker.take() {
                                if !waker.will_wake(cx.waker()) {
                                    waker.wake();
                                }
                            }
                            *waker = Some(cx.waker().clone());
                            return Poll::Pending;
                        }
                        Some(nonce) => {
                            use crate::relay::tcprelay::proxy_stream::protocol::v2::{
                                get_now_timestamp,
                                Aead2022TcpResponseHeaderRef,
                            };

                            let header = Aead2022TcpResponseHeaderRef {
                                timestamp: get_now_timestamp(),
                                request_salt: nonce,
                            };

                            let mut buffer = BytesMut::with_capacity(header.serialized_len());
                            header.write_to_buf(&mut buffer);

                            *(this.writer_state) = ProxyServerStreamWriteState::WriteHeader(buffer, 0);
                        }
                    }
                }
                #[cfg(feature = "aead-cipher-2022")]
                ProxyServerStreamWriteState::WriteHeader(ref buf, ref mut buf_pos) => {
                    let n = ready!(this.stream.as_mut().poll_write_encrypted(cx, &buf[*buf_pos..]))?;
                    *buf_pos += n;

                    if *buf_pos >= buf.len() {
                        *(this.writer_state) = ProxyServerStreamWriteState::Established;
                    }
                }
            }
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().stream.poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().stream.poll_shutdown(cx)
    }
}
