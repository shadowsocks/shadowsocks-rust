//! Fake DNS UDP server

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use hickory_resolver::proto::op::{Message, response_code::ResponseCode};
use log::error;
use shadowsocks::{ServerAddr, lookup_then, net::UdpSocket as ShadowUdpSocket};
use tokio::time;

use crate::local::context::ServiceContext;

use super::{manager::FakeDnsManager, processor::handle_dns_request};

/// Fake DNS UDP server instance
pub struct FakeDnsUdpServer {
    listener: ShadowUdpSocket,
    manager: Arc<FakeDnsManager>,
}

impl FakeDnsUdpServer {
    pub(crate) async fn new(
        context: Arc<ServiceContext>,
        client_config: &ServerAddr,
        manager: Arc<FakeDnsManager>,
    ) -> io::Result<Self> {
        let listener = match *client_config {
            ServerAddr::SocketAddr(ref saddr) => {
                ShadowUdpSocket::listen_with_opts(saddr, context.accept_opts()).await?
            }
            ServerAddr::DomainName(ref dname, port) => {
                lookup_then!(context.context_ref(), dname, port, |addr| {
                    ShadowUdpSocket::listen_with_opts(&addr, context.accept_opts()).await
                })?
                .1
            }
        };

        Ok(Self { listener, manager })
    }

    /// Get UDP local address
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Start server accept loop
    pub async fn run(self) -> io::Result<()> {
        let mut buffer = [0u8; 65535];
        loop {
            let (n, peer_addr) = match self.listener.recv_from(&mut buffer).await {
                Ok(n) => n,
                Err(err) => {
                    error!("fakedns UDP recv_from failed, error: {}", err);
                    time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            let req_message = match Message::from_vec(&buffer[..n]) {
                Ok(m) => m,
                Err(err) => {
                    error!("failed to parse DNS request, error: {}", err);
                    continue;
                }
            };

            let rsp_message = match handle_dns_request(&req_message, &self.manager).await {
                Ok(m) => m,
                Err(err) => {
                    error!("failed to handle DNS request, error: {}", err);

                    Message::error_msg(req_message.id(), req_message.op_code(), ResponseCode::ServFail)
                }
            };

            let rsp_buffer = rsp_message.to_vec()?;
            let _ = self.listener.send_to(&rsp_buffer, peer_addr).await;
        }
    }
}
