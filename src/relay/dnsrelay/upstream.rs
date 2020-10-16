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
    net::UdpSocket,
};
use trust_dns_proto::{
    op::{Message, Query},
    rr::{DNSClass, Name, RData, RecordType},
};

#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use tokio::net::UnixStream;

use crate::{
    config::{Config, ServerConfig},
    context::SharedContext,
    relay::{socks5::Address, tcprelay::ProxyStream},
};

#[derive(Debug)]
pub enum LocalUpstream {
    Udp(UdpUpstream),
    // Tcp(TcpUpstream),
    #[cfg(unix)]
    UnixSocket(UnixSocketUpstream),
}

impl LocalUpstream {
    pub fn new(config: &Config) -> LocalUpstream {
        #[cfg(target_os = "android")]
        return LocalUpstream::UnixSocket(UnixSocketUpstream {
            path: config.local_dns_path.clone().expect("local query DNS path"),
        });
        #[cfg(not(target_os = "android"))]
        LocalUpstream::Udp(UdpUpstream {
            server: config.local_dns_addr.clone().expect("local query DNS address"),
        })
    }

    pub async fn lookup(&self, query: &Query) -> io::Result<Message> {
        match self {
            LocalUpstream::Udp(upstream) => upstream.lookup(query).await,
            // LocalUpstream::Tcp(upstream) => upstream.lookup(query),
            #[cfg(unix)]
            LocalUpstream::UnixSocket(upstream) => upstream.lookup(query).await,
        }
    }

    pub async fn lookup_ip(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let mut name = Name::from_utf8(host)?;
        name.set_fqdn(true);
        let mut queryv4 = Query::new();
        queryv4.set_query_class(DNSClass::IN);
        queryv4.set_name(name);
        let mut queryv6 = queryv4.clone();
        queryv4.set_query_type(RecordType::A);
        queryv6.set_query_type(RecordType::AAAA);
        let (responsev4, responsev6) = tokio::try_join!(self.lookup(&queryv4), self.lookup(&queryv6))?;
        macro_rules! parse {
            ($response:expr) => {
                $response.answers().iter().filter_map(|rec| match rec.rdata() {
                    RData::A(ref ip) => Some(SocketAddr::new(IpAddr::V4(ip.clone()), port)),
                    RData::AAAA(ref ip) => Some(SocketAddr::new(IpAddr::V6(ip.clone()), port)),
                    _ => None,
                })
            };
        }
        Ok(parse!(responsev4).chain(parse!(responsev6)).collect())
    }
}

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

pub async fn read_message<T: AsyncReadExt + Unpin>(stream: &mut T) -> io::Result<Message> {
    let mut res_buffer = vec![0; 2];
    stream.read_exact(&mut res_buffer[0..2]).await?;

    let size = BigEndian::read_u16(&res_buffer[0..2]) as usize;
    let mut res_buffer = vec![0; size];
    stream.read_exact(&mut res_buffer[0..size]).await?;

    Ok(Message::from_vec(&res_buffer)?)
}

pub async fn write_message<T: AsyncWriteExt + Unpin>(stream: &mut T, message: &Message) -> io::Result<()> {
    let req_buffer = message.to_vec()?;
    let size = req_buffer.len();
    let mut send_buffer = vec![0; size + 2];

    BigEndian::write_u16(&mut send_buffer[0..2], size as u16);
    send_buffer[2..size + 2].copy_from_slice(&req_buffer[0..size]);
    stream.write_all(&send_buffer[0..size + 2]).await
}

async fn stream_lookup<T>(query: &Query, stream: &mut T) -> io::Result<Message>
where
    T: AsyncReadExt + AsyncWriteExt + Unpin,
{
    write_message(stream, &generate_query_message(query)).await?;
    read_message(stream).await
}

#[derive(Debug)]
pub struct UdpUpstream {
    pub server: SocketAddr,
}

#[async_trait]
impl Upstream for UdpUpstream {
    async fn lookup(&self, query: &Query) -> io::Result<Message> {
        let socket = UdpSocket::bind(SocketAddr::new(
            match self.server {
                SocketAddr::V4(..) => IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                SocketAddr::V6(..) => IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
            },
            0,
        ))
        .await?;
        socket.connect(self.server).await?;
        socket.send(&generate_query_message(query).to_vec()?).await?;
        let mut response = vec![0; 512];
        let len = socket.recv(&mut response).await?;
        Ok(Message::from_vec(&response[..len])?)
    }
}

// #[derive(Debug)]
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
        f.debug_struct("ProxyTcpUpstream").field("ns", &self.ns).finish()
    }
}

#[async_trait]
impl<F> Upstream for ProxyTcpUpstream<F>
where
    F: Fn() -> ServerConfig + Send + Sync,
{
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
