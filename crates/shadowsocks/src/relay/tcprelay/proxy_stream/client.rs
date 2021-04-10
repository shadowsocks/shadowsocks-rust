//! TCP stream for communicating with shadowsocks' proxy server

use std::{
    io::{self, ErrorKind},
    pin::Pin,
    task::{self, Poll},
};

use bytes::{BufMut, BytesMut};
use futures::ready;
use log::trace;
use once_cell::sync::Lazy;
use pin_project::pin_project;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    time,
};

use crate::{
    config::ServerConfig,
    context::SharedContext,
    net::{ConnectOpts, TcpStream as OutboundTcpStream},
    relay::{
        socks5::Address,
        tcprelay::crypto_io::{CryptoStream, CryptoStreamReadHalf, CryptoStreamWriteHalf},
    },
};

enum ProxyClientStreamWriteState {
    Connect(Address),
    Connecting(BytesMut),
    Connected,
}

/// A stream for sending / receiving data stream from remote server via shadowsocks' proxy server
#[pin_project]
pub struct ProxyClientStream<S> {
    #[pin]
    stream: CryptoStream<S>,
    state: ProxyClientStreamWriteState,
    context: SharedContext,
}

static DEFAULT_CONNECT_OPTS: Lazy<ConnectOpts> = Lazy::new(Default::default);

impl ProxyClientStream<TcpStream> {
    /// Connect to target `addr` via shadowsocks' server configured by `svr_cfg`
    pub async fn connect<A>(
        context: SharedContext,
        svr_cfg: &ServerConfig,
        addr: A,
    ) -> io::Result<ProxyClientStream<TcpStream>>
    where
        A: Into<Address>,
    {
        ProxyClientStream::connect_with_opts(context, svr_cfg, addr, &DEFAULT_CONNECT_OPTS).await
    }

    /// Connect to target `addr` via shadowsocks' server configured by `svr_cfg`
    pub async fn connect_with_opts<A>(
        context: SharedContext,
        svr_cfg: &ServerConfig,
        addr: A,
        opts: &ConnectOpts,
    ) -> io::Result<ProxyClientStream<TcpStream>>
    where
        A: Into<Address>,
    {
        ProxyClientStream::connect_with_opts_map(context, svr_cfg, addr, opts, |s| s).await
    }
}

impl<S> ProxyClientStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Connect to target `addr` via shadowsocks' server configured by `svr_cfg`, maps `TcpStream` to customized stream with `map_fn`
    pub async fn connect_map<A, F>(
        context: SharedContext,
        svr_cfg: &ServerConfig,
        addr: A,
        map_fn: F,
    ) -> io::Result<ProxyClientStream<S>>
    where
        A: Into<Address>,
        F: FnOnce(TcpStream) -> S,
    {
        ProxyClientStream::connect_with_opts_map(context, svr_cfg, addr, &DEFAULT_CONNECT_OPTS, map_fn).await
    }

    /// Connect to target `addr` via shadowsocks' server configured by `svr_cfg`, maps `TcpStream` to customized stream with `map_fn`
    pub async fn connect_with_opts_map<A, F>(
        context: SharedContext,
        svr_cfg: &ServerConfig,
        addr: A,
        opts: &ConnectOpts,
        map_fn: F,
    ) -> io::Result<ProxyClientStream<S>>
    where
        A: Into<Address>,
        F: FnOnce(TcpStream) -> S,
    {
        let stream = match svr_cfg.timeout() {
            Some(d) => {
                match time::timeout(
                    d,
                    OutboundTcpStream::connect_server_with_opts(&context, svr_cfg.external_addr(), opts),
                )
                .await
                {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => return Err(e),
                    Err(..) => {
                        return Err(io::Error::new(
                            ErrorKind::TimedOut,
                            format!("connect {} timeout", svr_cfg.addr()),
                        ))
                    }
                }
            }
            None => OutboundTcpStream::connect_server_with_opts(&context, svr_cfg.external_addr(), opts).await?,
        };

        trace!(
            "connected tcp remote {} (outbound: {}) with {:?}",
            svr_cfg.addr(),
            svr_cfg.external_addr(),
            opts
        );

        Ok(ProxyClientStream::from_stream(
            context,
            map_fn(stream.into()),
            svr_cfg,
            addr,
        ))
    }

    /// Create a `ProxyClientStream` with a connected `stream` to a shadowsocks' server
    ///
    /// NOTE: `stream` must be connected to the server with the same configuration as `svr_cfg`, otherwise strange errors would occurs
    pub fn from_stream<A>(context: SharedContext, stream: S, svr_cfg: &ServerConfig, addr: A) -> ProxyClientStream<S>
    where
        A: Into<Address>,
    {
        let addr = addr.into();
        let stream = CryptoStream::from_stream(&context, stream, svr_cfg.method(), svr_cfg.key());

        ProxyClientStream {
            stream,
            state: ProxyClientStreamWriteState::Connect(addr),
            context,
        }
    }

    /// Get reference to the underlying stream
    pub fn get_ref(&self) -> &S {
        self.stream.get_ref()
    }

    /// Get mutable reference to the underlying stream
    pub fn get_mut(&mut self) -> &mut S {
        self.stream.get_mut()
    }

    /// Consumes the `ProxyClientStream` and return the underlying stream
    pub fn into_inner(self) -> S {
        self.stream.into_inner()
    }
}

impl<S> AsyncRead for ProxyClientStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut this = self.project();
        this.stream.poll_read_decrypted(cx, &this.context, buf)
    }
}

impl<S> AsyncWrite for ProxyClientStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        let mut this = self.project();

        loop {
            match this.state {
                ProxyClientStreamWriteState::Connect(ref addr) => {
                    // Target Address should be sent with the first packet together,
                    // which would prevent from being detected by connection features.

                    let addr_length = addr.serialized_len();

                    let mut buffer = BytesMut::with_capacity(addr_length + buf.len());
                    addr.write_to_buf(&mut buffer);
                    buffer.put_slice(buf);

                    // Save the concatenated buffer before it is written successfully.
                    // APIs require buffer to be kept alive before Poll::Ready
                    //
                    // Proactor APIs like IOCP on Windows, pointers of buffers have to be kept alive
                    // before IO completion.
                    *(this.state) = ProxyClientStreamWriteState::Connecting(buffer);
                }
                ProxyClientStreamWriteState::Connecting(ref buffer) => {
                    let n = ready!(this.stream.poll_write_encrypted(cx, &buffer))?;

                    // In general, poll_write_encrypted should perform like write_all.
                    debug_assert!(n == buffer.len());

                    *(this.state) = ProxyClientStreamWriteState::Connected;

                    // NOTE:
                    // poll_write will return Ok(0) if buf.len() == 0
                    // But for the first call, this function will eventually send the handshake packet (IV/Salt + ADDR) to the remote address.
                    //
                    // https://github.com/shadowsocks/shadowsocks-rust/issues/232
                    //
                    // For protocols that requires *Server Hello* message, like FTP, clients won't send anything to the server until server sends handshake messages.
                    // This could be achieved by calling poll_write with an empty input buffer.
                    return Ok(buf.len()).into();
                }
                ProxyClientStreamWriteState::Connected => {
                    return this.stream.poll_write_encrypted(cx, buf);
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

impl<S> ProxyClientStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Splits into reader and writer halves
    pub fn into_split(self) -> (ProxyClientStreamReadHalf<S>, ProxyClientStreamWriteHalf<S>) {
        // Cannot split if stream is still pending
        assert!(
            !matches!(self.state, ProxyClientStreamWriteState::Connecting(..)),
            "stream is pending on writing the first packet"
        );
        let (reader, writer) = self.stream.into_split();
        (
            ProxyClientStreamReadHalf {
                reader,
                context: self.context,
            },
            ProxyClientStreamWriteHalf {
                writer,
                state: self.state,
            },
        )
    }
}

/// Owned read half produced by `ProxyClientStream::into_split`
#[pin_project]
pub struct ProxyClientStreamReadHalf<S> {
    #[pin]
    reader: CryptoStreamReadHalf<S>,
    context: SharedContext,
}

impl<S> AsyncRead for ProxyClientStreamReadHalf<S>
where
    S: AsyncRead + Unpin,
{
    #[inline]
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut this = self.project();
        this.reader.poll_read_decrypted(cx, &this.context, buf)
    }
}

/// Owned write half produced by `ProxyClientStream::into_split`
#[pin_project]
pub struct ProxyClientStreamWriteHalf<S> {
    #[pin]
    writer: CryptoStreamWriteHalf<S>,
    state: ProxyClientStreamWriteState,
}

impl<S> AsyncWrite for ProxyClientStreamWriteHalf<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        let mut this = self.project();

        loop {
            match this.state {
                ProxyClientStreamWriteState::Connect(ref addr) => {
                    // Target Address should be sent with the first packet together,
                    // which would prevent from being detected by connection features.

                    let addr_length = addr.serialized_len();

                    let mut buffer = BytesMut::with_capacity(addr_length + buf.len());
                    addr.write_to_buf(&mut buffer);
                    buffer.put_slice(buf);

                    // Save the concatenated buffer before it is written successfully.
                    // APIs require buffer to be kept alive before Poll::Ready
                    //
                    // Proactor APIs like IOCP on Windows, pointers of buffers have to be kept alive
                    // before IO completion.
                    *(this.state) = ProxyClientStreamWriteState::Connecting(buffer);
                }
                ProxyClientStreamWriteState::Connecting(ref buffer) => {
                    let n = ready!(this.writer.poll_write_encrypted(cx, &buffer))?;

                    // In general, poll_write_encrypted should perform like write_all.
                    debug_assert!(n == buffer.len());

                    *(this.state) = ProxyClientStreamWriteState::Connected;

                    // NOTE:
                    // poll_write will return Ok(0) if buf.len() == 0
                    // But for the first call, this function will eventually send the handshake packet (IV/Salt + ADDR) to the remote address.
                    //
                    // https://github.com/shadowsocks/shadowsocks-rust/issues/232
                    //
                    // For protocols that requires *Server Hello* message, like FTP, clients won't send anything to the server until server sends handshake messages.
                    // This could be achieved by calling poll_write with an empty input buffer.
                    return Ok(buf.len()).into();
                }
                ProxyClientStreamWriteState::Connected => {
                    return this.writer.poll_write_encrypted(cx, buf);
                }
            }
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().writer.poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().writer.poll_shutdown(cx)
    }
}
