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
    time,
};

#[cfg(feature = "aead-cipher-2022")]
use crate::context::Context;
use crate::{
    config::ServerConfig,
    context::SharedContext,
    crypto::CipherKind,
    net::{ConnectOpts, TcpStream as OutboundTcpStream},
    relay::{
        socks5::Address,
        tcprelay::crypto_io::{CryptoRead, CryptoStream, CryptoWrite},
    },
};

enum ProxyClientStreamWriteState {
    Connect(Address),
    Connecting(BytesMut),
    Connected,
}

enum ProxyClientStreamReadState {
    #[cfg(feature = "aead-cipher-2022")]
    WaitHeader(BytesMut, usize),
    Established,
}

/// A stream for sending / receiving data stream from remote server via shadowsocks' proxy server
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
        let stream = CryptoStream::from_stream(&context, stream, svr_cfg.method(), svr_cfg.key());

        #[cfg(not(feature = "aead-cipher-2022"))]
        let reader_state = ProxyClientStreamReadState::Established;

        #[cfg(feature = "aead-cipher-2022")]
        let reader_state = if svr_cfg.method().is_aead_2022() {
            // AEAD 2022 has a respond header
            ProxyClientStreamReadState::WaitHeader(BytesMut::new(), 0)
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

#[cfg(feature = "aead-cipher-2022")]
fn poll_read_aead_2022_header<S>(
    context: &Context,
    mut stream: Pin<&mut CryptoStream<S>>,
    cx: &mut task::Context<'_>,
    header_buf: &mut BytesMut,
    header_pos: &mut usize,
) -> Poll<io::Result<()>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use bytes::Buf;
    use std::time::SystemTime;

    // AEAD 2022 TCP Response Header
    //
    // +-------+-------+-------+-------+-------+-------+-------+-------+-------+
    // | TYPE  | UNIX TIMESTAMP                                                |
    // +-------+-------+-------+-------+-------+-------+-------+-------+-------+
    // | Request SALT (Variable ...)
    // +-------+-------+-------+-------+-------+-------+-------+-------+-------+

    const SERVER_STREAM_TYPE: u8 = 1;
    const SERVER_STREAM_TIMESTAMP_MAX_DIFF: u64 = 30;

    // Initialize buffer
    let method = stream.method();
    if header_buf.is_empty() {
        header_buf.resize(1 + 8 + method.salt_len(), 0);
        *header_pos = 0;
    }

    while *header_pos < header_buf.len() {
        let remaining_buf = &mut header_buf[*header_pos..];
        let mut read_buf = ReadBuf::new(remaining_buf);

        ready!(stream.as_mut().poll_read_decrypted(cx, context, &mut read_buf))?;

        *header_pos += read_buf.filled().len();
    }

    // Done reading TCP header, check all the fields

    let stream_type = header_buf.get_u8();
    if stream_type != SERVER_STREAM_TYPE {
        return Err(io::Error::new(
            ErrorKind::Other,
            format!("received TCP response header with wrong type {}", stream_type),
        ))
        .into();
    }

    let timestamp = header_buf.get_u64();
    let now = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => panic!("SystemTime::now() is before UNIX Epoch!"),
    };

    if now.abs_diff(timestamp) > SERVER_STREAM_TIMESTAMP_MAX_DIFF {
        return Err(io::Error::new(
            ErrorKind::Other,
            format!("received TCP response header with aged timestamp: {}", timestamp),
        ))
        .into();
    }

    let salt = &header_buf[..];
    if salt != stream.sent_nonce() {
        return Err(io::Error::new(
            ErrorKind::Other,
            "received TCP response header with unmatched salt",
        ))
        .into();
    }

    Ok(()).into()
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
                    return this.stream.poll_read_decrypted(cx, this.context, buf);
                }
                #[cfg(feature = "aead-cipher-2022")]
                ProxyClientStreamReadState::WaitHeader(ref mut buf, ref mut buf_pos) => {
                    ready!(poll_read_aead_2022_header(
                        this.context,
                        this.stream.as_mut(),
                        cx,
                        buf,
                        buf_pos,
                    ))?;
                    *(this.reader_state) = ProxyClientStreamReadState::Established;
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

    #[cfg(feature = "aead-cipher-2022")]
    if method.is_aead_2022() {
        // TCP Request Header
        //
        // +-------+-------+-------+-------+-------+-------+-------+-------+-------+
        // | TYPE  | UNIX TIMESTAMP                                                |
        // +-------+-------+-------+-------+-------+-------+-------+-------+-------+
        // | ADDR (Variable ...)
        // +-------+-------+-------+-------+-------+-------+-------+-------+-------+
        // | PADDING SIZE  | PADDING (Variable ...)
        // +-------+-------+-------+-------+-------+-------+-------+-------+-------+
        //
        // Client -> Server TYPE=0

        use rand::{rngs::SmallRng, Rng, SeedableRng};
        use std::{cell::RefCell, time::SystemTime};

        const CLIENT_STREAM_TYPE: u8 = 0;
        const MAX_PADDING_SIZE: usize = 900;

        thread_local! {
            static PADDING_RNG: RefCell<SmallRng> = RefCell::new(SmallRng::from_entropy());
        }

        let padding_size = if buf.is_empty() {
            PADDING_RNG.with(|rng| rng.borrow_mut().gen::<usize>() % MAX_PADDING_SIZE)
        } else {
            // If handshake with data buffer, then padding is not required and should be 0 for letting TFO work properly.
            0
        };

        buffer.reserve(1 + 8 + addr_length + 2 + padding_size);
        buffer.put_u8(CLIENT_STREAM_TYPE);

        let timestamp = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(n) => n.as_secs(),
            Err(_) => panic!("SystemTime::now() is before UNIX Epoch!"),
        };
        buffer.put_u64(timestamp);

        addr.write_to_buf(&mut buffer);

        buffer.put_u16(padding_size as u16);

        if padding_size > 0 {
            unsafe {
                buffer.advance_mut(padding_size);
            }
        }
    }

    let _ = method;

    // STREAM / AEAD protocol, append the Address before payload
    if buffer.is_empty() {
        buffer.reserve(addr_length + buf.len());
        addr.write_to_buf(&mut buffer);
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
