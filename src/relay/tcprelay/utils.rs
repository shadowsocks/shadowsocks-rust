//! Utility functions

use std::{io, net::SocketAddr};

use log::trace;
use tokio::net::{TcpSocket, TcpStream};

/// Connecting to a specific target with TCP protocol
///
/// Optionally we can bind to a local address for connecting
pub async fn connect_tcp_stream(addr: &SocketAddr, outbound_addr: &Option<SocketAddr>) -> io::Result<TcpStream> {
    match *outbound_addr {
        None => {
            trace!("connecting {}", addr);

            // Connect with tokio's default API directly
            TcpStream::connect(addr).await
        }
        Some(ref bind_addr) => {
            // Create TcpStream manually from socket
            // These functions may not behave exactly the same as tokio's TcpStream::connect

            trace!("connecting {} from {}", addr, bind_addr);

            let socket = match *addr {
                SocketAddr::V4(..) => TcpSocket::new_v4()?,
                SocketAddr::V6(..) => TcpSocket::new_v6()?,
            };

            // Bind to local outbound address
            //
            // Common failure: EADDRINUSE
            socket.bind(*bind_addr)?;

            // Connect to the target
            //
            // FIXME: This function is not documented as it may be deleted in the future
            //
            // mio 0.6.x (tokio 0.2.x is depending on it) will set stream into non-block mode
            // unix: https://github.com/tokio-rs/mio/blob/v0.6.x/src/sys/unix/tcp.rs#L28
            // windows: https://github.com/tokio-rs/mio/blob/v0.6.x/src/sys/windows/tcp.rs#L118
            //
            // We have to let tokio calls connect for us. Because we don't have a chance to wait until the socket is actually connected
            socket.connect(*addr).await
        }
    }
}
