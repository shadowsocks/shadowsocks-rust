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
    if opts.tcp.nodelay {
        stream.set_nodelay(true)?;
    }

    Ok(())
}
