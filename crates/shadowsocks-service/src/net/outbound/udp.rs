//! Outbound UDP relay through a SOCKS5-only proxy chain.
//!
//! Establishes a SOCKS5 `UDP ASSOCIATE` against every hop in the
//! configured chain, then transports each datagram by nesting one
//! [`UdpAssociateHeader`] per hop. The resulting [`OutboundProxyDatagram`]
//! implements [`DatagramSocket`] / [`DatagramSend`] / [`DatagramReceive`]
//! so it can be plugged directly into [`ProxySocket::from_socket`] in
//! place of a raw UDP socket.
//!
//! Supported only when **every** hop is SOCKS5 (see
//! [`OutboundProxyClient::supports_udp`]); the dispatcher in
//! `local::net::udp::association` is responsible for picking this path
//! vs. the direct one.

use std::{
    io::{self, Cursor},
    net::SocketAddr,
    sync::Mutex,
    task::{Context, Poll, ready},
};

use bytes::{BufMut, BytesMut};
use log::{debug, trace};
use shadowsocks::{
    context::SharedContext,
    lookup_then,
    net::{AddrFamily, ConnectOpts, TcpStream as ShadowTcpStream, UdpSocket as ShadowUdpSocket},
    relay::{
        socks5::{Address, UdpAssociateHeader},
        udprelay::{DatagramReceive, DatagramSend, DatagramSocket},
    },
};
use tokio::io::ReadBuf;

use super::{
    OutboundProxyClient, OutboundProxyKind, TcpDialer, chain::connect_chain_for_udp_associate,
    socks5::Socks5Negotiator,
};

/// One SOCKS5 UDP relay hop. The `assoc_tcp` keep-alive connection must
/// outlive every datagram exchanged through this hop (RFC 1928).
struct Socks5UdpRelay {
    /// Keep-alive TCP control connection. We hold the bare [`ShadowTcpStream`]
    /// rather than an [`super::OutboundProxyStream`] so the relay (and
    /// therefore [`OutboundProxyDatagram`]) is `Sync` — the chain builder
    /// never produces a non-TCP variant for SOCKS5-only chains, so this
    /// downcast always succeeds.
    #[allow(dead_code)]
    assoc_tcp: ShadowTcpStream,
    relay_addr: Address,
    relay_socket_addr: Option<SocketAddr>,
}

impl Socks5UdpRelay {
    fn relay_addr(&self) -> &Address {
        &self.relay_addr
    }
}

/// Multi-hop SOCKS5 UDP relay implementing the
/// [`DatagramSocket`] / [`DatagramSend`] / [`DatagramReceive`] triple.
///
/// The chain is built once at association time. Each `send` then nests
/// `hops` SOCKS5 UDP headers around the upper-layer payload (the inner-
/// most header carries the **final target** address — for sslocal /
/// ssserver this is always the configured `target` baked in at
/// construction time, namely the ss-server's UDP external address).
pub struct OutboundProxyDatagram {
    socket: ShadowUdpSocket,
    relays: Vec<Socks5UdpRelay>,
    /// Inner-most target address — recorded once at construction time
    /// and used as the SOCKS5 UDP innermost destination on every send.
    /// For sslocal / ssserver outbound chains this is the ss-server's
    /// UDP external address.
    target: Address,
    /// Address the local UDP socket is `connect()`ed to (the first hop's
    /// relay address). Reported to upper layers as the "peer" / source
    /// from which `recv_from` returns datagrams.
    first_hop_addr: SocketAddr,
    /// Reusable receive scratch buffer (header stripping requires reading
    /// the full datagram before we know the payload offset).
    recv_scratch: Mutex<Vec<u8>>,
}

impl OutboundProxyDatagram {
    /// Establish UDP relays through every hop of `client`.
    ///
    /// * `target` is the inner-most destination (typically the ss-server's
    ///   UDP external address).
    /// * `dialer` is used to dial all TCP control connections.
    /// * `connect_opts` configures the local UDP socket.
    pub async fn associate<D>(
        client: &OutboundProxyClient,
        context: &SharedContext,
        dialer: &D,
        connect_opts: &ConnectOpts,
        target: Address,
    ) -> io::Result<Self>
    where
        D: TcpDialer + Sync,
    {
        let hops = client.hops();
        if hops.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty outbound proxy chain",
            ));
        }
        for hop in hops {
            if !matches!(hop.kind, OutboundProxyKind::Socks5 { .. }) {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "outbound UDP relay requires every hop to be SOCKS5",
                ));
            }
        }

        // Bind the local UDP socket using the shadowsocks helper so
        // `ConnectOpts` (bind address, fwmark, ...) is honoured.
        let socket = ShadowUdpSocket::connect_any_with_opts(AddrFamily::Ipv4, connect_opts).await?;

        let local_udp_addr = socket.local_addr()?;
        trace!("outbound udp local socket bound to {}", local_udp_addr);

        let mut relays: Vec<Socks5UdpRelay> = Vec::with_capacity(hops.len());

        // The "announce" address tells the next hop the source it should
        // expect datagrams from. For the first hop this is the local UDP
        // socket; for later hops it is the relay address granted by the
        // previous hop.
        let mut announce: Address = Address::from(local_udp_addr);

        for (idx, hop) in hops.iter().enumerate() {
            // Build a TCP control connection that *terminates* at `hop`
            // (i.e. previous hops are traversed via SOCKS5 TcpConnect).
            let mut tcp = connect_chain_for_udp_associate(hops, idx, dialer).await?;

            let auth = match &hop.kind {
                OutboundProxyKind::Socks5 { auth } => auth,
                _ => unreachable!("guarded above"),
            };

            let resp = Socks5Negotiator::establish_udp_associate(&mut tcp, announce.clone(), auth)
                .await
                .map_err(io::Error::other)?;

            // For a SOCKS5-only chain the byte stream is always still raw
            // TCP after the handshake (no TLS / HTTP layers were
            // applied). Recover the underlying TcpStream so the relay
            // struct stays `Sync`.
            let tcp = tcp.try_into_tcp().map_err(|_| {
                io::Error::other(
                    "internal error: outbound UDP relay produced a non-TCP keep-alive stream",
                )
            })?;

            let relay_addr = resp.address;
            let relay_socket_addr = match relay_addr {
                Address::SocketAddress(sa) => Some(sa),
                Address::DomainNameAddress(ref name, port) => {
                    // Resolve domain-name relay addresses via the
                    // shadowsocks shared resolver — matches what a direct
                    // ProxySocket::connect_with_opts does.
                    let (sa, _) = lookup_then!(context, name, port, |sa| {
                        Ok::<SocketAddr, io::Error>(sa)
                    })?;
                    Some(sa)
                }
            };

            trace!(
                "outbound udp hop {}: relay_addr={} (resolved={:?}), announce={}",
                idx, relay_addr, relay_socket_addr, announce
            );

            // Next hop's announce = this hop's relay address.
            announce = match relay_socket_addr {
                Some(sa) => Address::from(sa),
                None => relay_addr.clone(),
            };

            relays.push(Socks5UdpRelay {
                assoc_tcp: tcp,
                relay_addr,
                relay_socket_addr,
            });
        }

        let first_hop_addr = relays[0]
            .relay_socket_addr
            .ok_or_else(|| io::Error::other("first SOCKS5 UDP relay returned an unresolved domain"))?;

        // Connect the local UDP socket to the first hop so subsequent
        // sends can use `send` instead of `send_to`.
        socket.connect(first_hop_addr).await?;

        debug!(
            "outbound udp chain established: {} hop(s), first_hop={}, target={}",
            relays.len(),
            first_hop_addr,
            target,
        );

        Ok(Self {
            socket,
            relays,
            target,
            first_hop_addr,
            recv_scratch: Mutex::new(Vec::new()),
        })
    }

    /// Number of SOCKS5 hops the chain consists of.
    pub fn hop_count(&self) -> usize {
        self.relays.len()
    }

    /// Wrap `payload` in N nested SOCKS5 UDP headers, where N is the
    /// number of hops. The inner-most header carries `self.target`.
    fn encode(&self, payload: &[u8]) -> BytesMut {
        let n = self.relays.len();

        // Header[i] addr = relays[i+1].relay_addr() for i < n-1, or
        // self.target for i == n-1.
        let mut total = payload.len();
        for i in 0..n {
            let addr = if i + 1 < n {
                self.relays[i + 1].relay_addr()
            } else {
                &self.target
            };
            total += UdpAssociateHeader::new(0, addr.clone()).serialized_len();
        }

        let mut buf = BytesMut::with_capacity(total);
        for i in 0..n {
            let addr = if i + 1 < n {
                self.relays[i + 1].relay_addr().clone()
            } else {
                self.target.clone()
            };
            UdpAssociateHeader::new(0, addr).write_to_buf(&mut buf);
        }
        buf.put_slice(payload);
        buf
    }

    /// Strip N nested SOCKS5 UDP headers from a freshly received datagram.
    /// Returns the inner-most reported source address and the payload
    /// offset.
    fn decode(&self, recv_buf: &[u8]) -> io::Result<(Address, usize)> {
        let n = self.relays.len();
        let mut cur = Cursor::new(recv_buf);
        let mut last_addr: Option<Address> = None;

        for _ in 0..n {
            // `UdpAssociateHeader::read_from` is async over an
            // `AsyncRead`. Cursor's `AsyncRead` impl yields synchronously,
            // so polling the future once always completes.
            let fut = std::pin::pin!(UdpAssociateHeader::read_from(&mut cur));
            match futures::FutureExt::now_or_never(fut) {
                Some(Ok(h)) => last_addr = Some(h.address),
                Some(Err(err)) => {
                    return Err(io::Error::other(format!(
                        "outbound udp: failed to parse SOCKS5 UDP header: {err}"
                    )));
                }
                None => unreachable!("Cursor read_from should be synchronous"),
            }
        }

        let pos = cur.position() as usize;
        Ok((last_addr.expect("relays is non-empty"), pos))
    }
}

impl DatagramSocket for OutboundProxyDatagram {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

impl DatagramSend for OutboundProxyDatagram {
    fn poll_send(&self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let wire = self.encode(buf);
        let sent = ready!(self.socket.poll_send(cx, &wire))?;
        if sent == wire.len() {
            // Report the upper-layer payload size (matches what
            // ProxySocket expects from a direct UDP send).
            Poll::Ready(Ok(buf.len()))
        } else {
            Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)))
        }
    }

    fn poll_send_to(&self, cx: &mut Context<'_>, buf: &[u8], _target: SocketAddr) -> Poll<io::Result<usize>> {
        // The first-hop relay is what we actually send to on the wire;
        // the upper layer's `target` (typically the ss-server) is already
        // baked into the inner-most SOCKS5 UDP header via `self.target`.
        let _ = _target;
        self.poll_send(cx, buf)
    }

    fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.socket.poll_send_ready(cx)
    }
}

impl DatagramReceive for OutboundProxyDatagram {
    fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        // Receive into our scratch, strip headers, then copy payload into
        // the caller's buffer.
        let mut scratch = self.recv_scratch.lock().expect("recv scratch poisoned");
        let needed = buf.remaining() + 1024;
        if scratch.len() < needed {
            scratch.resize(needed, 0);
        }
        let mut tmp = ReadBuf::new(&mut scratch);
        ready!(self.socket.poll_recv(cx, &mut tmp))?;
        let n = tmp.filled().len();
        let (_inner_src, pos) = self.decode(&scratch[..n])?;
        let payload_len = n - pos;
        if payload_len > buf.remaining() {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::InvalidData)));
        }
        buf.put_slice(&scratch[pos..n]);
        Poll::Ready(Ok(()))
    }

    fn poll_recv_from(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<SocketAddr>> {
        // The upper layer wants the source address. We report the first-
        // hop relay we actually received from (the only socket-level
        // address available); the inner-most SOCKS5 source is discarded
        // because the upper layer will decrypt and parse the ss-server's
        // own packet header anyway.
        ready!(self.poll_recv(cx, buf))?;
        Poll::Ready(Ok(self.first_hop_addr))
    }

    fn poll_recv_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.socket.poll_recv_ready(cx)
    }
}
