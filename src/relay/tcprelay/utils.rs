//! Utility functions

use std::{io, net::SocketAddr};

use log::trace;
use socket2::{Domain, SockAddr, Socket, Type};
use tokio::net::TcpStream;

/// Connecting to a specific target with TCP protocol
///
/// Optionally we can bind to a local address for connecting
pub async fn connect_tcp_stream(addr: &SocketAddr, outbound_addr: &Option<SocketAddr>) -> io::Result<TcpStream> {
    match *outbound_addr {
        None => {
            trace!("Connecting {}", addr);

            // Connect with tokio's default API directly
            TcpStream::connect(addr).await
        }
        Some(ref bind_addr) => {
            // Create TcpStream manually from socket
            // These functions may not behave exactly the same as tokio's TcpStream::connect

            trace!("Connecting {} from {}", addr, bind_addr);

            let socket = match *addr {
                SocketAddr::V4(..) => Socket::new(Domain::ipv4(), Type::stream(), None)?,
                SocketAddr::V6(..) => Socket::new(Domain::ipv6(), Type::stream(), None)?,
            };

            // Bind to local outbound address
            //
            // Common failure: EADDRINUSE
            let bind_addr = SockAddr::from(*bind_addr);
            socket.bind(&bind_addr)?;

            // Connect to the target
            //
            // FIXME: This function is not documented as it may be deleted in the future
            //
            // mio 0.6.x (tokio 0.2.x is depending on it) will set stream into non-block mode
            // unix: https://github.com/tokio-rs/mio/blob/v0.6.x/src/sys/unix/tcp.rs#L28
            // windows: https://github.com/tokio-rs/mio/blob/v0.6.x/src/sys/windows/tcp.rs#L118
            //
            // We have to let tokio calls connect for us. Because we don't have a chance to wait until the socket is actually connected
            TcpStream::connect_std(socket.into_tcp_stream(), addr).await
        }
    }
}
