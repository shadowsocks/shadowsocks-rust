use std::{
    io,
    net::{IpAddr, SocketAddr},
};

use cfg_if::cfg_if;
use tokio::net::TcpSocket;

use super::ConnectOpts;

cfg_if! {
    if #[cfg(unix)] {
        mod unix;
        pub use self::unix::*;
    } else if #[cfg(windows)] {
        mod windows;
        pub use self::windows::*;
    }
}

fn set_common_sockopt_for_connect(addr: SocketAddr, socket: &TcpSocket, opts: &ConnectOpts) -> io::Result<()> {
    // Binds to IP address
    if let Some(ip) = opts.bind_local_addr {
        match (ip, addr.ip()) {
            (IpAddr::V4(..), IpAddr::V4(..)) => {
                socket.bind(SocketAddr::new(ip, 0))?;
            }
            (IpAddr::V6(..), IpAddr::V6(..)) => {
                socket.bind(SocketAddr::new(ip, 0))?;
            }
            _ => {}
        }
    }

    // Set `SO_SNDBUF`
    if let Some(buf_size) = opts.tcp.send_buffer_size {
        socket.set_send_buffer_size(buf_size)?;
    }

    // Set `SO_RCVBUF`
    if let Some(buf_size) = opts.tcp.recv_buffer_size {
        socket.set_recv_buffer_size(buf_size)?;
    }

    Ok(())
}

fn set_common_sockopt_after_connect(stream: &tokio::net::TcpStream, opts: &ConnectOpts) -> io::Result<()> {
    stream.set_nodelay(opts.tcp.nodelay)?;
    set_common_sockopt_after_connect_sys(stream, opts)?;

    Ok(())
}

#[cfg(unix)]
#[inline]
fn set_common_sockopt_after_connect_sys(stream: &tokio::net::TcpStream, opts: &ConnectOpts) -> io::Result<()> {
    use socket2::{Socket, TcpKeepalive};
    use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};

    let socket = unsafe { Socket::from_raw_fd(stream.as_raw_fd()) };

    macro_rules! try_sockopt {
        ($socket:ident . $func:ident ($($arg:expr),*)) => {
            match $socket . $func ($($arg),*) {
                Ok(e) => e,
                Err(err) => {
                    let _ = socket.into_raw_fd();
                    return Err(err);
                }
            }
        };
    }

    if let Some(keepalive_duration) = opts.tcp.keepalive {
        #[allow(unused_mut)]
        let mut keepalive = TcpKeepalive::new().with_time(keepalive_duration);

        #[cfg(any(
            target_os = "freebsd",
            target_os = "fuchsia",
            target_os = "linux",
            target_os = "netbsd",
            target_vendor = "apple",
        ))]
        {
            keepalive = keepalive.with_interval(keepalive_duration);
        }

        try_sockopt!(socket.set_tcp_keepalive(&keepalive));
    }

    let _ = socket.into_raw_fd();
    Ok(())
}

#[cfg(windows)]
#[inline]
fn set_common_sockopt_after_connect_sys(stream: &tokio::net::TcpStream, opts: &ConnectOpts) -> io::Result<()> {
    use socket2::{Socket, TcpKeepalive};
    use std::os::windows::io::{AsRawSocket, FromRawSocket, IntoRawSocket};

    let socket = unsafe { Socket::from_raw_socket(stream.as_raw_socket()) };

    macro_rules! try_sockopt {
        ($socket:ident . $func:ident ($($arg:expr),*)) => {
            match $socket . $func ($($arg),*) {
                Ok(e) => e,
                Err(err) => {
                    let _ = socket.into_raw_socket();
                    return Err(err);
                }
            }
        };
    }

    if let Some(keepalive_duration) = opts.tcp.keepalive {
        let keepalive = TcpKeepalive::new()
            .with_time(keepalive_duration)
            .with_interval(keepalive_duration);
        try_sockopt!(socket.set_tcp_keepalive(&keepalive));
    }

    let _ = socket.into_raw_socket();
    Ok(())
}

#[cfg(all(not(windows), not(unix)))]
#[inline]
fn set_common_sockopt_after_connect_sys(_: &tokio::net::TcpStream, _: &ConnectOpts) -> io::Result<()> {
    Ok(())
}
