use std::{io, net::SocketAddr};

use shadowsocks::net::AcceptOpts;
use tokio::net::{TcpListener, TcpStream};

use crate::{
    config::RedirType,
    local::redir::redir_ext::{TcpListenerRedirExt, TcpStreamRedirExt},
};

impl TcpListenerRedirExt for TcpListener {
    async fn bind_redir(_ty: RedirType, _addr: SocketAddr, _accept_opts: AcceptOpts) -> io::Result<TcpListener> {
        unimplemented!("TCP transparent proxy is not supported on this platform")
    }
}

impl TcpStreamRedirExt for TcpStream {
    fn destination_addr(&self, _ty: RedirType) -> io::Result<SocketAddr> {
        unimplemented!("TCP transparent proxy is not supported on this platform")
    }
}
