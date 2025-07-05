use std::{
    io,
    net::SocketAddr,
    os::unix::io::{AsRawFd, FromRawFd, IntoRawFd},
};

use cfg_if::cfg_if;
use log::warn;
use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};
use tokio::net::UdpSocket;

use crate::net::{AcceptOpts, AddrFamily, ConnectOpts, TcpSocketOpts, is_dual_stack_addr, sys::socket_bind_dual_stack};

cfg_if! {
    if #[cfg(any(target_os = "linux", target_os = "android"))] {
        mod linux;
        pub use self::linux::*;
    } else if #[cfg(any(target_os = "freebsd",
                        target_os = "openbsd",
                        target_os = "netbsd",
                        target_os = "dragonfly",
                        target_os = "macos",
                        target_os = "ios",
                        target_os = "watchos",
                        target_os = "tvos"))] {
        mod bsd;
        pub use self::bsd::*;
    } else {
        mod others;
        pub use self::others::*;
    }
}

pub mod uds;

/// Create a `UdpSocket` binded to `addr`
pub async fn create_inbound_udp_socket(addr: &SocketAddr, ipv6_only: bool) -> io::Result<UdpSocket> {
    let set_dual_stack = is_dual_stack_addr(addr);

    let socket = if !set_dual_stack {
        UdpSocket::bind(addr).await?
    } else {
        let socket = Socket::new(Domain::for_address(*addr), Type::DGRAM, Some(Protocol::UDP))?;
        socket_bind_dual_stack(&socket, addr, ipv6_only)?;

        // UdpSocket::from_std requires socket to be non-blocked
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket.into())?
    };

    let addr_family = match addr {
        SocketAddr::V4(..) => AddrFamily::Ipv4,
        SocketAddr::V6(..) => AddrFamily::Ipv6,
    };
    if let Err(err) = set_disable_ip_fragmentation(addr_family, &socket) {
        warn!("failed to disable IP fragmentation, error: {}", err);
    }

    Ok(socket)
}

#[inline]
fn set_tcp_keepalive(socket: &Socket, tcp: &TcpSocketOpts) -> io::Result<()> {
    if let Some(intv) = tcp.keepalive {
        #[allow(unused_mut)]
        let mut keepalive = TcpKeepalive::new().with_time(intv);

        #[cfg(any(
            target_os = "freebsd",
            target_os = "fuchsia",
            target_os = "linux",
            target_os = "netbsd",
            target_vendor = "apple",
        ))]
        {
            keepalive = keepalive.with_interval(intv);
        }

        cfg_if! {
            if #[cfg(any(target_os = "linux", target_os = "android"))] {
                // FIXME: Linux Kernel doesn't support setting TCP Keep Alive. (MPTCP)
                // SO_KEEPALIVE works fine. But TCP_KEEPIDLE, TCP_KEEPINTV are not supported.
                // https://github.com/multipath-tcp/mptcp_net-next/issues/383
                // https://github.com/multipath-tcp/mptcp_net-next/issues/353
                if let Err(err) = socket.set_tcp_keepalive(&keepalive) {
                    log::debug!("set TCP keep-alive with time & interval failed with error: {:?}", err);

                    // Try again without time & interval
                    let keepalive = TcpKeepalive::new();
                    socket.set_tcp_keepalive(&keepalive)?;
                }
            } else {
                socket.set_tcp_keepalive(&keepalive)?;
            }
        }
    }

    Ok(())
}

#[inline(always)]
fn socket_call_warp<S: AsRawFd, F: FnOnce(&Socket) -> io::Result<()>>(stream: &S, f: F) -> io::Result<()> {
    let socket = unsafe { Socket::from_raw_fd(stream.as_raw_fd()) };
    let result = f(&socket);
    let _ = socket.into_raw_fd();
    result
}

pub fn set_common_sockopt_after_connect<S: AsRawFd>(stream: &S, opts: &ConnectOpts) -> io::Result<()> {
    socket_call_warp(stream, |socket| set_common_sockopt_after_connect_impl(socket, opts))
}

fn set_common_sockopt_after_connect_impl(socket: &Socket, opts: &ConnectOpts) -> io::Result<()> {
    if opts.tcp.nodelay {
        socket.set_tcp_nodelay(true)?;
    }

    set_tcp_keepalive(socket, &opts.tcp)?;

    Ok(())
}

pub fn set_common_sockopt_after_accept<S: AsRawFd>(stream: &S, opts: &AcceptOpts) -> io::Result<()> {
    socket_call_warp(stream, |socket| set_common_sockopt_after_accept_impl(socket, opts))
}

fn set_common_sockopt_after_accept_impl(socket: &Socket, opts: &AcceptOpts) -> io::Result<()> {
    if let Some(buf_size) = opts.tcp.send_buffer_size {
        socket.set_send_buffer_size(buf_size as usize)?;
    }

    if let Some(buf_size) = opts.tcp.recv_buffer_size {
        socket.set_recv_buffer_size(buf_size as usize)?;
    }

    socket.set_tcp_nodelay(opts.tcp.nodelay)?;

    set_tcp_keepalive(socket, &opts.tcp)?;

    Ok(())
}
