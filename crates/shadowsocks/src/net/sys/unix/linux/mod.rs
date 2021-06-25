use std::{
    io::{self, ErrorKind},
    mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream as StdTcpStream},
    ops::{Deref, DerefMut},
    os::unix::io::{AsRawFd, FromRawFd, IntoRawFd},
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{self, Poll},
};

use cfg_if::cfg_if;
use futures::ready;
use log::error;
use pin_project::pin_project;
use socket2::SockAddr;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpSocket, TcpStream as TokioTcpStream, UdpSocket},
};

use crate::net::{
    sys::{set_common_sockopt_after_connect, set_common_sockopt_for_connect},
    AddrFamily,
    ConnectOpts,
};

enum TcpStreamState {
    Connected,
    FastOpenConnect(SocketAddr),
    FastOpenWrite,
}

/// A `TcpStream` that supports TFO (TCP Fast Open)
#[pin_project(project = TcpStreamProj)]
pub struct TcpStream {
    #[pin]
    inner: TokioTcpStream,
    state: TcpStreamState,
}

impl TcpStream {
    pub async fn connect(addr: SocketAddr, opts: &ConnectOpts) -> io::Result<TcpStream> {
        let socket = match addr {
            SocketAddr::V4(..) => TcpSocket::new_v4()?,
            SocketAddr::V6(..) => TcpSocket::new_v6()?,
        };

        // Any traffic to localhost should not be protected
        // This is a workaround for VPNService
        #[cfg(target_os = "android")]
        if !addr.ip().is_loopback() {
            use std::time::Duration;
            use tokio::time;

            if let Some(ref path) = opts.vpn_protect_path {
                // RPC calls to `VpnService.protect()`
                // Timeout in 3 seconds like shadowsocks-libev
                match time::timeout(Duration::from_secs(3), vpn_protect(path, socket.as_raw_fd())).await {
                    Ok(Ok(..)) => {}
                    Ok(Err(err)) => return Err(err),
                    Err(..) => return Err(io::Error::new(ErrorKind::TimedOut, "protect() timeout")),
                }
            }
        }

        // Set SO_MARK for mark-based routing on Linux (since 2.6.25)
        // NOTE: This will require CAP_NET_ADMIN capability (root in most cases)
        if let Some(mark) = opts.fwmark {
            let ret = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    &mark as *const _ as *const _,
                    mem::size_of_val(&mark) as libc::socklen_t,
                )
            };
            if ret != 0 {
                let err = io::Error::last_os_error();
                error!("set SO_MARK error: {}", err);
                return Err(err);
            }
        }

        // Set SO_BINDTODEVICE for binding to a specific interface
        if let Some(ref iface) = opts.bind_interface {
            set_bindtodevice(&socket, iface)?;
        }

        set_common_sockopt_for_connect(addr, &socket, opts)?;

        if !opts.tcp.fastopen {
            // If TFO is not enabled, it just works like a normal TcpStream
            let stream = socket.connect(addr).await?;
            set_common_sockopt_after_connect(&stream, opts)?;

            return Ok(TcpStream {
                inner: stream,
                state: TcpStreamState::Connected,
            });
        }

        let mut connected = false;

        // TFO in Linux was supported since 3.7
        //
        // But TCP_FASTOPEN_CONNECT was supported since 4.1, so we have to be compatible with it
        static SUPPORT_TCP_FASTOPEN_CONNECT: AtomicBool = AtomicBool::new(true);
        if SUPPORT_TCP_FASTOPEN_CONNECT.load(Ordering::Relaxed) {
            unsafe {
                let enable: libc::c_int = 1;

                let ret = libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::IPPROTO_TCP,
                    libc::TCP_FASTOPEN_CONNECT,
                    &enable as *const _ as *const libc::c_void,
                    mem::size_of_val(&enable) as libc::socklen_t,
                );

                if ret != 0 {
                    let err = io::Error::last_os_error();
                    if let Some(libc::ENOPROTOOPT) = err.raw_os_error() {
                        // `TCP_FASTOPEN_CONNECT` is not supported, maybe kernel version < 4.11
                        // Fallback to `sendto` with `MSG_FASTOPEN` (Supported after 3.7)
                        SUPPORT_TCP_FASTOPEN_CONNECT.store(false, Ordering::Relaxed);
                    } else {
                        error!("set TCP_FASTOPEN_CONNECT error: {}", err);
                        return Err(err);
                    }
                } else {
                    connected = true;
                }
            }
        }

        let stream = if connected {
            // call connect() if TCP_FASTOPEN_CONNECT is set
            socket.connect(addr).await?
        } else {
            // call sendto() with MSG_FASTOPEN in poll_read
            TokioTcpStream::from_std(unsafe { StdTcpStream::from_raw_fd(socket.into_raw_fd()) })?
        };

        set_common_sockopt_after_connect(&stream, opts)?;

        Ok(TcpStream {
            inner: stream,
            state: if connected {
                TcpStreamState::FastOpenWrite
            } else {
                TcpStreamState::FastOpenConnect(addr)
            },
        })
    }
}

impl Deref for TcpStream {
    type Target = TokioTcpStream;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for TcpStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        loop {
            let TcpStreamProj { inner, state } = self.as_mut().project();

            match *state {
                TcpStreamState::Connected => return inner.poll_write(cx, buf),

                TcpStreamState::FastOpenConnect(addr) => {
                    // Fallback mode. Must be kernal < 4.11
                    //
                    // Uses sendto as BSD-like systems

                    let saddr = SockAddr::from(addr);

                    let stream = inner.get_mut();

                    // Ensure socket is writable
                    ready!(stream.poll_write_ready(cx))?;

                    let mut connecting = false;
                    let send_result = stream.try_write_io(|| {
                        unsafe {
                            let ret = libc::sendto(
                                stream.as_raw_fd(),
                                buf.as_ptr() as *const libc::c_void,
                                buf.len(),
                                libc::MSG_FASTOPEN,
                                saddr.as_ptr(),
                                saddr.len(),
                            );

                            if ret >= 0 {
                                Ok(ret as usize)
                            } else {
                                // Error occurs
                                let err = io::Error::last_os_error();

                                // EINPROGRESS
                                if let Some(libc::EINPROGRESS) = err.raw_os_error() {
                                    // For non-blocking socket, it returns the number of bytes queued (and transmitted in the SYN-data packet) if cookie is available.
                                    // If cookie is not available, it transmits a data-less SYN packet with Fast Open cookie request option and returns -EINPROGRESS like connect().
                                    //
                                    // So in this state. We have to loop again to call `poll_write` for sending the first packet.
                                    connecting = true;

                                    // Let `try_write_io` clears the write readiness.
                                    Err(ErrorKind::WouldBlock.into())
                                } else {
                                    // Other errors, including EAGAIN, EWOULDBLOCK
                                    Err(err)
                                }
                            }
                        }
                    });

                    match send_result {
                        Ok(n) => {
                            // Connected successfully with fast open
                            *state = TcpStreamState::Connected;
                            return Ok(n).into();
                        }
                        Err(ref err) if err.kind() == ErrorKind::WouldBlock => {
                            if connecting {
                                // Connecting with normal TCP handshakes, write the first packet after connected
                                *state = TcpStreamState::Connected;
                            }
                        }
                        Err(err) => return Err(err).into(),
                    }
                }

                TcpStreamState::FastOpenWrite => {
                    // First `write` after `TCP_FASTOPEN_CONNECT`
                    // Kernel >= 4.11

                    let stream = inner.get_mut();

                    // Ensure socket is writable
                    ready!(stream.poll_write_ready(cx))?;

                    let mut connecting = false;
                    let send_result = stream.try_write_io(|| {
                        unsafe {
                            let ret = libc::send(stream.as_raw_fd(), buf.as_ptr() as *const libc::c_void, buf.len(), 0);

                            if ret >= 0 {
                                Ok(ret as usize)
                            } else {
                                let err = io::Error::last_os_error();
                                // EINPROGRESS
                                if let Some(libc::EINPROGRESS) = err.raw_os_error() {
                                    // For non-blocking socket, it returns the number of bytes queued (and transmitted in the SYN-data packet) if cookie is available.
                                    // If cookie is not available, it transmits a data-less SYN packet with Fast Open cookie request option and returns -EINPROGRESS like connect().
                                    //
                                    // So in this state. We have to loop again to call `poll_write` for sending the first packet.
                                    connecting = true;

                                    // Let `poll_write_io` clears the write readiness.
                                    Err(ErrorKind::WouldBlock.into())
                                } else {
                                    // Other errors, including EAGAIN, EWOULDBLOCK
                                    Err(err)
                                }
                            }
                        }
                    });

                    match send_result {
                        Ok(n) => {
                            // Connected successfully with fast open
                            *state = TcpStreamState::Connected;
                            return Ok(n).into();
                        }
                        Err(ref err) if err.kind() == ErrorKind::WouldBlock => {
                            if connecting {
                                // Connecting with normal TCP handshakes, write the first packet after connected
                                *state = TcpStreamState::Connected;
                            }
                        }
                        Err(err) => return Err(err).into(),
                    }
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

/// Enable `TCP_FASTOPEN`
///
/// `TCP_FASTOPEN` was supported since Linux 3.7
pub fn set_tcp_fastopen<S: AsRawFd>(socket: &S) -> io::Result<()> {
    let queue: libc::c_int = 5;

    unsafe {
        let ret = libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN,
            &queue as *const _ as *const libc::c_void,
            mem::size_of_val(&queue) as libc::socklen_t,
        );

        if ret != 0 {
            let err = io::Error::last_os_error();
            error!("set TCP_FASTOPEN error: {}", err);
            return Err(err);
        }
    }

    Ok(())
}

/// Create a `UdpSocket` for connecting to `addr`
pub async fn create_outbound_udp_socket(af: AddrFamily, config: &ConnectOpts) -> io::Result<UdpSocket> {
    let bind_addr = match (af, config.bind_local_addr) {
        (AddrFamily::Ipv4, Some(IpAddr::V4(ip))) => SocketAddr::new(ip.into(), 0),
        (AddrFamily::Ipv6, Some(IpAddr::V6(ip))) => SocketAddr::new(ip.into(), 0),
        (AddrFamily::Ipv4, ..) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
        (AddrFamily::Ipv6, ..) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
    };

    let socket = UdpSocket::bind(bind_addr).await?;

    // Any traffic except localhost should be protected
    // This is a workaround for VPNService
    #[cfg(target_os = "android")]
    {
        use std::time::Duration;
        use tokio::time;

        if let Some(ref path) = config.vpn_protect_path {
            // RPC calls to `VpnService.protect()`
            // Timeout in 3 seconds like shadowsocks-libev
            match time::timeout(Duration::from_secs(3), vpn_protect(path, socket.as_raw_fd())).await {
                Ok(Ok(..)) => {}
                Ok(Err(err)) => return Err(err),
                Err(..) => return Err(io::Error::new(ErrorKind::TimedOut, "protect() timeout")),
            }
        }
    }

    // Set SO_MARK for mark-based routing on Linux (since 2.6.25)
    // NOTE: This will require CAP_NET_ADMIN capability (root in most cases)
    if let Some(mark) = config.fwmark {
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &mark as *const _ as *const _,
                mem::size_of_val(&mark) as libc::socklen_t,
            )
        };
        if ret != 0 {
            let err = io::Error::last_os_error();
            error!("set SO_MARK error: {}", err);
            return Err(err);
        }
    }

    // Set SO_BINDTODEVICE for binding to a specific interface
    if let Some(ref iface) = config.bind_interface {
        set_bindtodevice(&socket, iface)?;
    }

    Ok(socket)
}

fn set_bindtodevice<S: AsRawFd>(socket: &S, iface: &str) -> io::Result<()> {
    let iface_bytes = iface.as_bytes();

    unsafe {
        let ret = libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            iface_bytes.as_ptr() as *const _ as *const libc::c_void,
            iface_bytes.len() as libc::socklen_t,
        );

        if ret != 0 {
            let err = io::Error::last_os_error();
            error!("set SO_BINDTODEVICE error: {}", err);
            return Err(err);
        }
    }

    Ok(())
}

cfg_if! {
    if #[cfg(target_os = "android")] {
        use std::path::Path;
        use std::os::unix::io::RawFd;

        mod uds;

        /// This is a RPC for Android to `protect()` socket for connecting to remote servers
        ///
        /// https://developer.android.com/reference/android/net/VpnService#protect(java.net.Socket)
        ///
        /// More detail could be found in [shadowsocks-android](https://github.com/shadowsocks/shadowsocks-android) project.
        async fn vpn_protect<P: AsRef<Path>>(protect_path: P, fd: RawFd) -> io::Result<()> {
            use tokio::io::AsyncReadExt;

            let mut stream = self::uds::UnixStream::connect(protect_path).await?;

            // send fds
            let dummy: [u8; 1] = [1];
            let fds: [RawFd; 1] = [fd];
            stream.send_with_fd(&dummy, &fds).await?;

            // receive the return value
            let mut response = [0; 1];
            stream.read_exact(&mut response).await?;

            if response[0] == 0xFF {
                return Err(io::Error::new(ErrorKind::Other, "protect() failed"));
            }

            Ok(())
        }
    }
}
