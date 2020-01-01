//! Normal TCP wrappers

use std::io;

use log::warn;
use tokio::net::{TcpListener, TcpStream};

#[inline]
pub async fn bind_listener(addr: &SocketAddr) -> io::Result<TcpListener> {
    warn!("Server didn't build with `tfo` feature enabled, consider rebuilding it with `--features tfo` or setting `fast_open` to false");

    TcpListener::bind(addr).await
}

#[inline]
pub async fn connect_stream(addr: &SocketAddr) -> io::Result<TcpStream> {
    warn!("Server didn't build with `tfo` feature enabled, consider rebuilding it with `--features tfo` or setting `fast_open` to false");

    TcpStream::connect(addr).await
}
