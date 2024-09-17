//! TCP stream for communicating with shadowsocks' proxy server

use std::{
    io::{self, ErrorKind},
    pin::Pin,
    task::{self, Poll},
};

use bytes::{BufMut, BytesMut};
use cfg_if::cfg_if;
use futures::ready;
use log::trace;
use once_cell::sync::Lazy;
use pin_project::pin_project;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time,
};

#[cfg(feature = "aead-cipher-2022")]
use crate::relay::get_aead_2022_padding_size;
use crate::{
    config::ServerConfig,
    context::SharedContext,
    crypto::CipherKind,
    net::{ConnectOpts, TcpStream as OutboundTcpStream},
    relay::{
        socks5::Address,
        tcprelay::crypto_io::{CryptoRead, CryptoStream, CryptoWrite, StreamType},
    },
};

#[derive(Debug)]
enum ProxyClientStreamWriteState {
    Connect(Address),
    Connecting(BytesMut),
    Connected,
}

#[derive(Debug)]
enum ProxyClientStreamReadState {
    #[cfg(feature = "aead-cipher-2022")]
    CheckRequestNonce,
    Established,
}

/// A stream for sending / receiving data stream from remote server via shadowsocks' proxy server
#[derive(Debug)]
#[pin_project]
pub struct ProxyClientStream<S> {
    #[pin]
    stream: CryptoStream<S>,
    writer_state: ProxyClientStreamWriteState,
    reader_state: ProxyClientStreamReadState,
    context: SharedContext,
}

static DEFAULT_CONNECT_OPTS: Lazy<ConnectOpts> = Lazy::new(Default::default);

impl ProxyClientStream<OutboundTcpStream> {
    /// Connect to target `addr` via shadowsocks' server configured by `svr_cfg`
    pub async fn connect<A>(
        context: SharedContext,
        svr_cfg: &ServerConfig,
        addr: A,
    ) -> io::Result<ProxyClientStream<OutboundTcpStream>>
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
    ) -> io::Result<ProxyClientStream<OutboundTcpStream>>
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
        F: FnOnce(OutboundTcpStream) -> S,
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
        F: FnOnce(OutboundTcpStream) -> S,
    {
        let stream = match svr_cfg.timeout() {
            Some(d) => {
                match time::timeout(
                    d,
                    OutboundTcpStream::connect_server_with_opts(&context, svr_cfg.tcp_external_addr(), opts),
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
            None => OutboundTcpStream::connect_server_with_opts(&context, svr_cfg.tcp_external_addr(), opts).await?,
        };

        trace!(
            "connected tcp remote {} (outbound: {}) with {:?}",
            svr_cfg.addr(),
            svr_cfg.tcp_external_addr(),
            opts
        );

        Ok(ProxyClientStream::from_stream(context, map_fn(stream), svr_cfg, addr))
    }

    /// Create a `ProxyClientStream` with a connected `stream` to a shadowsocks' server
    ///
    /// NOTE: `stream` must be connected to the server with the same configuration as `svr_cfg`, otherwise strange errors would occurs
    pub fn from_stream<A>(context: SharedContext, stream: S, svr_cfg: &ServerConfig, addr: A) -> ProxyClientStream<S>
    where
        A: Into<Address>,
    {
        let addr = addr.into();
        let stream = CryptoStream::from_stream_with_identity(
            &context,
            stream,
            StreamType::Client,
            svr_cfg.method(),
            svr_cfg.key(),
            svr_cfg.identity_keys(),
            None,
        );

        #[cfg(not(feature = "aead-cipher-2022"))]
        let reader_state = ProxyClientStreamReadState::Established;

        #[cfg(feature = "aead-cipher-2022")]
        let reader_state = if svr_cfg.method().is_aead_2022() {
            // AEAD 2022 has a respond header
            ProxyClientStreamReadState::CheckRequestNonce
        } else {
            ProxyClientStreamReadState::Established
        };

        ProxyClientStream {
            stream,
            writer_state: ProxyClientStreamWriteState::Connect(addr),
            reader_state,
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
        #[allow(unused_mut)]
        let mut this = self.project();

        #[allow(clippy::never_loop)]
        loop {
            match this.reader_state {
                ProxyClientStreamReadState::Established => {
                    return this
                        .stream
                        .poll_read_decrypted(cx, this.context, buf)
                        .map_err(Into::into);
                }
                #[cfg(feature = "aead-cipher-2022")]
                ProxyClientStreamReadState::CheckRequestNonce => {
                    ready!(this.stream.as_mut().poll_read_decrypted(cx, this.context, buf))?;

                    // REQUEST_NONCE should be in the respond packet (header) of AEAD-2022.
                    //
                    // If received_request_nonce() is None, then:
                    // 1. method.salt_len() == 0, no checking required.
                    // 2. TCP stream read() returns EOF before receiving the header, no checking required.
                    //
                    // poll_read_decrypted will wait until the first non-zero size data chunk.
                    let (data_chunk_count, _) = this.stream.current_data_chunk_remaining();
                    if data_chunk_count > 0 {
                        // data_chunk_count > 0, so the reader received at least 1 data chunk.

                        let sent_nonce = this.stream.sent_nonce();
                        let sent_nonce = if sent_nonce.is_empty() { None } else { Some(sent_nonce) };
                        if sent_nonce != this.stream.received_request_nonce() {
                            return Err(io::Error::new(
                                ErrorKind::Other,
                                "received TCP response header with unmatched salt",
                            ))
                            .into();
                        }

                        *(this.reader_state) = ProxyClientStreamReadState::Established;
                    }

                    return Ok(()).into();
                }
            }
        }
    }
}

#[inline]
fn make_first_packet_buffer(method: CipherKind, addr: &Address, buf: &[u8]) -> BytesMut {
    // Target Address should be sent with the first packet together,
    // which would prevent from being detected.

    let addr_length = addr.serialized_len();
    let mut buffer = BytesMut::new();

    cfg_if! {
        if #[cfg(feature = "aead-cipher-2022")] {
            let padding_size = get_aead_2022_padding_size(buf);
            let header_length = if method.is_aead_2022() {
                addr_length + 2 + padding_size + buf.len()
            } else {
                addr_length + buf.len()
            };
        } else {
            let _ = method;
            let header_length = addr_length + buf.len();
        }
    }

    buffer.reserve(header_length);

    // STREAM / AEAD / AEAD2022 protocol, append the Address before payload
    addr.write_to_buf(&mut buffer);

    #[cfg(feature = "aead-cipher-2022")]
    if method.is_aead_2022() {
        buffer.put_u16(padding_size as u16);

        if padding_size > 0 {
            unsafe {
                buffer.advance_mut(padding_size);
            }
        }
    }

    buffer.put_slice(buf);

    buffer
}

impl<S> AsyncWrite for ProxyClientStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        let this = self.project();

        loop {
            match this.writer_state {
                ProxyClientStreamWriteState::Connect(ref addr) => {
                    let buffer = make_first_packet_buffer(this.stream.method(), addr, buf);

                    // Save the concatenated buffer before it is written successfully.
                    // APIs require buffer to be kept alive before Poll::Ready
                    //
                    // Proactor APIs like IOCP on Windows, pointers of buffers have to be kept alive
                    // before IO completion.
                    *(this.writer_state) = ProxyClientStreamWriteState::Connecting(buffer);
                }
                ProxyClientStreamWriteState::Connecting(ref buffer) => {
                    let n = ready!(this.stream.poll_write_encrypted(cx, buffer))?;

                    // In general, poll_write_encrypted should perform like write_all.
                    debug_assert!(n == buffer.len());

                    *(this.writer_state) = ProxyClientStreamWriteState::Connected;

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
                    return this.stream.poll_write_encrypted(cx, buf).map_err(Into::into);
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
