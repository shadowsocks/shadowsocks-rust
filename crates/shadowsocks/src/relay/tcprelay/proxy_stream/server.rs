//! A TCP stream for communicating with shadowsocks' proxy client

use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};

use bytes::Bytes;
use futures::ready;
use pin_project::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    config::ServerUserManager,
    context::SharedContext,
    crypto::CipherKind,
    relay::{
        socks5::Address,
        tcprelay::{
            crypto_io::{CryptoRead, CryptoStream, CryptoWrite, StreamType},
            proxy_stream::protocol::TcpRequestHeader,
        },
    },
};

#[derive(Debug)]
enum ProxyServerStreamWriteState {
    #[cfg(feature = "aead-cipher-2022")]
    PrepareHeader(Option<std::task::Waker>),
    Established,
}

/// A stream for communicating with shadowsocks' proxy client
#[derive(Debug)]
#[pin_project]
pub struct ProxyServerStream<S> {
    #[pin]
    stream: CryptoStream<S>,
    context: SharedContext,
    writer_state: ProxyServerStreamWriteState,
    has_handshaked: bool,
}

impl<S> ProxyServerStream<S> {
    /// Create a `ProxyServerStream` from a connection stream
    pub fn from_stream(context: SharedContext, stream: S, method: CipherKind, key: &[u8]) -> Self {
        Self::from_stream_with_user_manager(context, stream, method, key, None)
    }

    /// Create a `ProxyServerStream` from a connection stream
    ///
    /// Set `user_manager` to enable support of verifying EIH users.
    pub fn from_stream_with_user_manager(
        context: SharedContext,
        stream: S,
        method: CipherKind,
        key: &[u8],
        user_manager: Option<Arc<ServerUserManager>>,
    ) -> Self {
        #[cfg(feature = "aead-cipher-2022")]
        let writer_state = if method.is_aead_2022() {
            ProxyServerStreamWriteState::PrepareHeader(None)
        } else {
            ProxyServerStreamWriteState::Established
        };

        #[cfg(not(feature = "aead-cipher-2022"))]
        let writer_state = ProxyServerStreamWriteState::Established;

        const EMPTY_IDENTITY: [Bytes; 0] = [];
        Self {
            stream: CryptoStream::from_stream_with_identity(
                &context,
                stream,
                StreamType::Server,
                method,
                key,
                &EMPTY_IDENTITY,
                user_manager,
            ),
            context,
            writer_state,
            has_handshaked: false,
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
        if self.has_handshaked {
            return Err(io::Error::other("stream is already handshaked"));
        }

        self.has_handshaked = true;
        let header = TcpRequestHeader::read_from(self.stream.method(), self).await?;

        #[cfg(feature = "aead-cipher-2022")]
        if let TcpRequestHeader::Aead2022(ref header) = header {
            use log::warn;

            // AEAD-2022 SPEC
            //
            // Padding: If the client is not sending payload along with the header, a random padding MUST be added.
            //
            // Check here preventing security risk causing by misimplementation clients.
            if header.padding_size == 0 {
                let (chunk_count, chunk_remaining) = self.stream.current_data_chunk_remaining();
                if chunk_count == 1 && chunk_remaining == 0 {
                    // Header is the end of the data chunk, so no payload is in the first chunk, and padding == 0.
                    // REJECT insecure clients.
                    return Err(io::Error::other("no payload in first data chunk, and padding is 0"));
                } else if chunk_count > 1 {
                    warn!(
                        "tcp header is separated in {} chunks, client is not following the AEAD-2022 spec",
                        chunk_count,
                    );
                }
            }
        }
        Ok(header.addr())
    }
}

impl<S> AsyncRead for ProxyServerStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if !self.has_handshaked {
            return Err(io::Error::other("stream is not handshaked yet")).into();
        }

        let this = self.project();
        ready!(this.stream.poll_read_decrypted(cx, this.context, buf))?;

        // Wakeup writer task because we have already received the salt
        #[cfg(feature = "aead-cipher-2022")]
        if let ProxyServerStreamWriteState::PrepareHeader(waker) = this.writer_state {
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
        #[allow(unused_mut)]
        let mut this = self.project();

        #[allow(clippy::never_loop)]
        loop {
            match *this.writer_state {
                ProxyServerStreamWriteState::Established => {
                    return this.stream.poll_write_encrypted(cx, buf).map_err(Into::into);
                }
                #[cfg(feature = "aead-cipher-2022")]
                ProxyServerStreamWriteState::PrepareHeader(ref mut waker) => {
                    if this.stream.set_request_nonce_with_received() {
                        *(this.writer_state) = ProxyServerStreamWriteState::Established;
                    } else {
                        // Reader didn't receive the salt from client yet.
                        if let Some(waker) = waker.take() {
                            if !waker.will_wake(cx.waker()) {
                                waker.wake();
                            }
                        }
                        *waker = Some(cx.waker().clone());
                        return Poll::Pending;
                    }
                }
            }
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().stream.poll_flush(cx).map_err(Into::into)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().stream.poll_shutdown(cx).map_err(Into::into)
    }
}
