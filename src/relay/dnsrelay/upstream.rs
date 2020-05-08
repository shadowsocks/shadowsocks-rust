use std::{
    fmt,
    fmt::{Debug, Formatter},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};
use rand::Rng;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket
};
use trust_dns_proto::op::{Message, Query};

#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use tokio::net::UnixStream;

use crate::{
    config::ServerConfig,
    context::SharedContext,
    relay::{
        socks5::Address,
        tcprelay::ProxyStream,
    },
};

#[async_trait]
pub trait Upstream: Debug {
    async fn lookup(&self, query: &Query) -> io::Result<Message>;
}

fn generate_query_message(query: &Query) -> Message {
    let mut message = Message::new();
    message.set_id(rand::thread_rng().gen());
    message.set_recursion_desired(true);
    message.add_query(query.clone());
    message
}

async fn stream_lookup<T>(query: &Query, stream: &mut T) -> io::Result<Message>
    where
        T: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let req_buffer = generate_query_message(query).to_vec()?;
    let size = req_buffer.len();
    let mut send_buffer = vec![0; size + 2];

    BigEndian::write_u16(&mut send_buffer[0..2], size as u16);
    send_buffer[2..size + 2].copy_from_slice(&req_buffer[0..size]);
    stream.write_all(&send_buffer[0..size + 2]).await?;

    let mut res_buffer = vec![0; 2];
    stream.read_exact(&mut res_buffer[0..2]).await?;

    let size = BigEndian::read_u16(&res_buffer[0..2]) as usize;
    let mut res_buffer = vec![0; size];
    stream.read_exact(&mut res_buffer[0..size]).await?;

    Ok(Message::from_vec(&res_buffer)?)
}

#[derive(Debug)]
pub struct UdpUpstream {
    pub server: SocketAddr,
}

#[async_trait]
impl Upstream for UdpUpstream {
    async fn lookup(&self, query: &Query) -> io::Result<Message> {
        let mut socket = UdpSocket::bind(SocketAddr::new(match self.server {
            SocketAddr::V4(..) => IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            SocketAddr::V6(..) => IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
        }, 0)).await?;
        socket.send_to(&generate_query_message(query).to_vec()?, self.server).await?;
        let mut response = vec![0; 512];
        socket.recv_from(&mut response).await?;
        Ok(Message::from_vec(&response)?)
    }
}

// pub struct TcpUpstream {
//     pub server: SocketAddr,
// }
//
// #[async_trait]
// impl Upstream for TcpUpstream {
//     async fn lookup(&self, query: &Query) -> Result<Message> {
//         unimplemented!()
//     }
// }

pub struct ProxyTcpUpstream<F> {
    pub context: SharedContext,
    pub svr_cfg: F,
    pub ns: Address,
}

impl<F> Debug for ProxyTcpUpstream<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyTcpUpstream")
            .field("ns", &self.ns)
            .finish()
    }
}

#[async_trait]
impl<F> Upstream for ProxyTcpUpstream<F> where F: Fn() -> ServerConfig + Send + Sync {
    async fn lookup(&self, query: &Query) -> io::Result<Message> {
        let mut stream = ProxyStream::connect_proxied(self.context.clone(), &(self.svr_cfg)(), &self.ns).await?;
        stream_lookup(query, &mut stream).await
    }
}

#[cfg(unix)]
#[derive(Debug)]
pub struct UnixSocketUpstream {
    pub path: PathBuf,
}

#[cfg(unix)]
#[async_trait]
impl Upstream for UnixSocketUpstream {
    async fn lookup(&self, query: &Query) -> io::Result<Message> {
        let mut stream = UnixStream::connect(&self.path).await?;
        stream_lookup(query, &mut stream).await
    }
}
