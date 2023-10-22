//! Local instance listener helpers

use std::io;

use shadowsocks::{config::ServerAddr, lookup_then, net::UdpSocket};

use crate::local::context::ServiceContext;

/// Create a standard UDP listener listening on `client_config`
pub async fn create_standard_udp_listener(
    context: &ServiceContext,
    client_config: &ServerAddr,
) -> io::Result<UdpSocket> {
    match client_config {
        ServerAddr::SocketAddr(saddr) => UdpSocket::listen_with_opts(saddr, context.accept_opts()).await,
        ServerAddr::DomainName(dname, port) => lookup_then!(context.context_ref(), dname, *port, |addr| {
            UdpSocket::listen_with_opts(&addr, context.accept_opts()).await
        })
        .map(|(_, s)| s),
    }
}
