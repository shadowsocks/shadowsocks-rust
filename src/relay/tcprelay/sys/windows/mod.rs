use std::{io, net::SocketAddr};

use async_trait::async_trait;
use tokio::net::TcpStream;

use crate::{config::RedirType, relay::redir::TcpListenerRedirExt};

pub struct TcpRedirListener;

impl TcpRedirListener {
    /// Create a TCP listener binding to `addr` and enable transparent proxy feature
    pub async fn bind(_ty: RedirType, _addr: &SocketAddr) -> io::Result<TcpRedirListener> {
        unimplemented!("TCP transparent proxy is not supported on Windows")
    }

    /// Get local bind addr for TcpListener
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        unimplemented!("TCP transparent proxy is not supported on Windows")
    }
}

#[async_trait]
impl TcpListenerRedirExt for TcpRedirListener {
    async fn accept_redir(&mut self) -> io::Result<(TcpStream, SocketAddr, Option<SocketAddr>)> {
        unimplemented!("TCP transparent proxy is not supported on Windows")
    }
}
