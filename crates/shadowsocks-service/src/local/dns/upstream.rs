//! DNS Relay Upstream

#[cfg(unix)]
use std::path::Path;
use std::{
    cmp::Ordering,
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use hickory_resolver::proto::{op::Message, ProtoError, ProtoErrorKind};
use log::{error, trace};
use lru_time_cache::{Entry, LruCache};
use rand::{thread_rng, Rng};
use shadowsocks::{
    config::ServerConfig,
    context::SharedContext,
    net::{ConnectOpts, TcpStream as ShadowTcpStream, UdpSocket as ShadowUdpSocket},
    relay::{
        tcprelay::ProxyClientStream,
        udprelay::{options::UdpSocketControlData, ProxySocket},
        Address,
    },
};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UdpSocket,
    time,
};

use crate::{
    local::net::udp::generate_client_session_id,
    net::{packet_window::PacketWindowFilter, FlowStat, MonProxySocket, MonProxyStream},
    DEFAULT_UDP_EXPIRY_DURATION,
};

/// Collection of various DNS connections
#[allow(clippy::large_enum_variant)]
pub enum DnsClient {
    TcpLocal {
        stream: ShadowTcpStream,
    },
    UdpLocal {
        socket: UdpSocket,
    },
    #[cfg(unix)]
    #[allow(dead_code)]
    UnixStream {
        stream: UnixStream,
    },
    TcpRemote {
        stream: ProxyClientStream<MonProxyStream<ShadowTcpStream>>,
    },
    UdpRemote {
        socket: MonProxySocket<ShadowUdpSocket>,
        ns: Address,
        control: UdpSocketControlData,
        server_windows: LruCache<u64, PacketWindowFilter>,
    },
}

impl DnsClient {
    /// Connect to local provided TCP DNS server
    pub async fn connect_tcp_local(ns: SocketAddr, connect_opts: &ConnectOpts) -> io::Result<DnsClient> {
        let stream = ShadowTcpStream::connect_with_opts(&ns, connect_opts).await?;
        Ok(DnsClient::TcpLocal { stream })
    }

    /// Connect to local provided UDP DNS server
    pub async fn connect_udp_local(ns: SocketAddr, connect_opts: &ConnectOpts) -> io::Result<DnsClient> {
        let socket = ShadowUdpSocket::connect_with_opts(&ns, connect_opts).await?.into();
        Ok(DnsClient::UdpLocal { socket })
    }

    #[cfg(unix)]
    /// Connect to local provided Unix Domain Socket DNS server, in TCP-like protocol
    pub async fn connect_unix_stream<P: AsRef<Path>>(path: &P) -> io::Result<DnsClient> {
        let stream = UnixStream::connect(path).await?;
        Ok(DnsClient::UnixStream { stream })
    }

    /// Connect to remote DNS server through proxy in TCP
    pub async fn connect_tcp_remote(
        context: SharedContext,
        svr_cfg: &ServerConfig,
        ns: &Address,
        connect_opts: &ConnectOpts,
        flow_stat: Arc<FlowStat>,
    ) -> io::Result<DnsClient> {
        let stream = ProxyClientStream::connect_with_opts_map(context, svr_cfg, ns, connect_opts, |s| {
            MonProxyStream::from_stream(s, flow_stat)
        })
        .await?;
        Ok(DnsClient::TcpRemote { stream })
    }

    /// Connect to remote DNS server through proxy in UDP
    pub async fn connect_udp_remote(
        context: SharedContext,
        svr_cfg: &ServerConfig,
        ns: Address,
        connect_opts: &ConnectOpts,
        flow_stat: Arc<FlowStat>,
    ) -> io::Result<DnsClient> {
        let socket = ProxySocket::connect_with_opts(context.clone(), svr_cfg, connect_opts).await?;
        let socket = MonProxySocket::from_socket(socket, flow_stat.clone());
        let mut control = UdpSocketControlData::default();
        control.client_session_id = generate_client_session_id();
        control.packet_id = 0; // AEAD-2022 Packet ID starts from 1
        Ok(DnsClient::UdpRemote {
            socket,
            ns,
            control,
            // NOTE: expiry duration should be configurable. But the Client is held by DnsClientCache, which expires very quickly.
            server_windows: LruCache::with_expiry_duration(DEFAULT_UDP_EXPIRY_DURATION),
        })
    }

    /// Make a DNS lookup
    #[allow(dead_code)]
    pub async fn lookup(&mut self, mut msg: Message) -> Result<Message, ProtoError> {
        self.inner_lookup(&mut msg).await
    }

    /// Make a DNS lookup with timeout
    pub async fn lookup_timeout(&mut self, mut msg: Message, timeout: Duration) -> Result<Message, ProtoError> {
        match time::timeout(timeout, self.inner_lookup(&mut msg)).await {
            Ok(Ok(msg)) => Ok(msg),
            Ok(Err(error)) => Err(error),
            Err(..) => Err(ProtoErrorKind::Timeout.into()),
        }
    }

    async fn inner_lookup(&mut self, msg: &mut Message) -> Result<Message, ProtoError> {
        // Make a random ID
        msg.set_id(thread_rng().gen());

        trace!("DNS lookup {:?}", msg);

        match *self {
            DnsClient::TcpLocal { ref mut stream } => stream_query(stream, msg).await,
            DnsClient::UdpLocal { ref socket } => {
                let bytes = msg.to_vec()?;
                socket.send(&bytes).await?;

                let mut recv_buf = [0u8; 512];
                let n = socket.recv(&mut recv_buf).await?;

                Message::from_vec(&recv_buf[..n])
            }
            #[cfg(unix)]
            DnsClient::UnixStream { ref mut stream } => stream_query(stream, msg).await,
            DnsClient::TcpRemote { ref mut stream } => stream_query(stream, msg).await,
            DnsClient::UdpRemote {
                ref mut socket,
                ref ns,
                ref mut control,
                ref mut server_windows,
            } => {
                control.packet_id = match control.packet_id.checked_add(1) {
                    Some(i) => i,
                    None => return Err(ProtoErrorKind::Message("packet id overflows").into()),
                };

                let bytes = msg.to_vec()?;
                socket.send_with_ctrl(ns, control, &bytes).await?;

                let mut recv_buf = [0u8; 512];
                let (n, _, recv_control) = socket.recv_with_ctrl(&mut recv_buf).await?;

                if let Some(server_control) = recv_control {
                    let filter = match server_windows.entry(server_control.server_session_id) {
                        Entry::Occupied(occ) => occ.into_mut(),
                        Entry::Vacant(vac) => vac.insert(PacketWindowFilter::new()),
                    };

                    if !filter.validate_packet_id(server_control.packet_id, u64::MAX) {
                        error!(
                            "dns client for {} packet_id {} out of window",
                            ns, server_control.packet_id
                        );

                        return Err(ProtoErrorKind::Message("packet id out of window").into());
                    }
                }

                Message::from_vec(&recv_buf[..n])
            }
        }
    }

    /// Check if the underlying connection is still connecting
    ///
    /// This will only work for TCP and UNIX Stream connections.
    /// UDP clients will always return `true`.
    pub async fn check_connected(&mut self) -> bool {
        #[cfg(unix)]
        fn check_peekable<F: std::os::unix::io::AsRawFd>(fd: &mut F) -> bool {
            let fd = fd.as_raw_fd();

            unsafe {
                let mut peek_buf = [0u8; 1];

                let ret = libc::recv(
                    fd,
                    peek_buf.as_mut_ptr() as *mut libc::c_void,
                    peek_buf.len(),
                    libc::MSG_PEEK | libc::MSG_DONTWAIT,
                );

                match ret.cmp(&0) {
                    // EOF, connection lost
                    Ordering::Equal => false,
                    // Data in buffer
                    Ordering::Greater => true,
                    Ordering::Less => {
                        let err = io::Error::last_os_error();
                        // EAGAIN, EWOULDBLOCK
                        // Still connected.
                        err.kind() == ErrorKind::WouldBlock
                    }
                }
            }
        }

        #[cfg(windows)]
        fn check_peekable<F: std::os::windows::io::AsRawSocket>(s: &mut F) -> bool {
            use windows_sys::{
                core::PSTR,
                Win32::Networking::WinSock::{recv, MSG_PEEK, SOCKET},
            };

            let sock = s.as_raw_socket() as SOCKET;

            unsafe {
                let mut peek_buf = [0u8; 1];

                let ret = recv(sock, peek_buf.as_mut_ptr() as PSTR, peek_buf.len() as i32, MSG_PEEK);

                match ret.cmp(&0) {
                    // EOF, connection lost
                    Ordering::Equal => false,
                    // Data in buffer
                    Ordering::Greater => true,
                    Ordering::Less => {
                        let err = io::Error::last_os_error();
                        // I have to trust the `s` have already set to non-blocking mode
                        // Because windows doesn't have MSG_DONTWAIT
                        err.kind() == ErrorKind::WouldBlock
                    }
                }
            }
        }

        match *self {
            DnsClient::TcpLocal { ref mut stream } => check_peekable(stream),
            DnsClient::UdpLocal { .. } => true,
            #[cfg(unix)]
            DnsClient::UnixStream { ref mut stream } => check_peekable(stream),
            DnsClient::TcpRemote { ref mut stream } => check_peekable(stream.get_mut().get_mut()),
            DnsClient::UdpRemote { .. } => true,
        }
    }
}

pub async fn stream_query<S>(stream: &mut S, r: &Message) -> Result<Message, ProtoError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut req_bytes = r.to_vec()?;

    // Prepend length
    let length = req_bytes.len();
    req_bytes.resize(length + 2, 0);
    req_bytes.copy_within(..length, 2);
    BigEndian::write_u16(&mut req_bytes[0..2], length as u16);

    stream.write_all(&req_bytes).await?;

    // Read response, [LENGTH][Message]
    let mut length_buf = [0u8; 2];
    stream.read_exact(&mut length_buf).await?;

    let length = BigEndian::read_u16(&length_buf);
    let mut rsp_bytes = BytesMut::with_capacity(length as usize);
    unsafe {
        rsp_bytes.advance_mut(length as usize);
    }
    stream.read_exact(&mut rsp_bytes).await?;

    Message::from_vec(&rsp_bytes)
}
