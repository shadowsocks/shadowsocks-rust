//! Fake DNS TCP server

use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use hickory_resolver::proto::{
    op::{Message, response_code::ResponseCode},
    serialize::binary::{BinEncodable, BinEncoder, EncodeMode},
};
use log::{error, trace};
use shadowsocks::{ServerAddr, lookup_then, net::TcpListener as ShadowTcpListener};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time,
};

use crate::local::context::ServiceContext;

use super::{manager::FakeDnsManager, processor::handle_dns_request};

/// Fake DNS TCP server
pub struct FakeDnsTcpServer {
    context: Arc<ServiceContext>,
    listener: ShadowTcpListener,
    manager: Arc<FakeDnsManager>,
}

impl FakeDnsTcpServer {
    pub(crate) async fn new(
        context: Arc<ServiceContext>,
        client_config: &ServerAddr,
        manager: Arc<FakeDnsManager>,
    ) -> io::Result<Self> {
        let listener = match *client_config {
            ServerAddr::SocketAddr(ref saddr) => {
                ShadowTcpListener::bind_with_opts(saddr, context.accept_opts()).await?
            }
            ServerAddr::DomainName(ref dname, port) => {
                lookup_then!(context.context_ref(), dname, port, |addr| {
                    ShadowTcpListener::bind_with_opts(&addr, context.accept_opts()).await
                })?
                .1
            }
        };

        Ok(Self {
            context,
            listener,
            manager,
        })
    }

    /// Get TCP local address
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Run TCP server loop
    pub async fn run(self) -> io::Result<()> {
        loop {
            let (stream, peer_addr) = match self.listener.accept().await {
                Ok(s) => s,
                Err(err) => {
                    error!("failed to accept Fake DNS connection, err: {}", err);
                    time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            trace!("Fake DNS accepted TCP client {}", peer_addr);

            let context = self.context.clone();
            let manager = self.manager.clone();
            tokio::spawn(async move {
                if let Err(err) = Self::handle_client(context, peer_addr, stream, manager).await {
                    error!(
                        "failed to handle Fake DNS tcp client, peer: {}, err: {}",
                        peer_addr, err
                    );
                }
            });
        }
    }

    async fn handle_client(
        _context: Arc<ServiceContext>,
        peer_addr: SocketAddr,
        mut stream: TcpStream,
        manager: Arc<FakeDnsManager>,
    ) -> io::Result<()> {
        let mut length_buf = [0u8; 2];
        let mut message_buf = BytesMut::new();

        loop {
            match stream.read_exact(&mut length_buf).await {
                Ok(..) => {}
                Err(ref err) if err.kind() == ErrorKind::UnexpectedEof => {
                    break;
                }
                Err(err) => {
                    error!("udp tcp {} read length failed, error: {}", peer_addr, err);
                    return Err(err);
                }
            }

            let length = BigEndian::read_u16(&length_buf) as usize;

            message_buf.clear();
            message_buf.reserve(length);
            unsafe {
                message_buf.advance_mut(length);
            }

            match stream.read_exact(&mut message_buf).await {
                Ok(..) => {}
                Err(err) => {
                    error!("dns tcp {} read message failed, error: {}", peer_addr, err);
                    return Err(err);
                }
            }

            let req_message = match Message::from_vec(&message_buf) {
                Ok(m) => m,
                Err(err) => {
                    error!("dns tcp {} parse message failed, error: {}", peer_addr, err);
                    return Err(err.into());
                }
            };

            let rsp_message = match handle_dns_request(&req_message, &manager).await {
                Ok(m) => m,
                Err(err) => {
                    error!("failed to handle DNS request, error: {}", err);

                    Message::error_msg(req_message.id(), req_message.op_code(), ResponseCode::ServFail)
                }
            };

            let mut rsp_buffer = Vec::with_capacity(2 + 512);
            rsp_buffer.resize(2, 0);
            let mut rsp_encoder = BinEncoder::with_offset(&mut rsp_buffer, 2, EncodeMode::Normal);
            rsp_message.emit(&mut rsp_encoder)?;

            let rsp_length = (rsp_buffer.len() - 2) as u16;
            BigEndian::write_u16(&mut rsp_buffer[0..2], rsp_length);

            stream.write_all(&rsp_buffer).await?;
        }

        Ok(())
    }
}
