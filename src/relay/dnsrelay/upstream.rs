#[cfg(unix)]
use std::path::PathBuf;
use std::{
    fmt,
    fmt::{Debug, Formatter},
    io,
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use log::trace;
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::UnixStream;
use trust_dns_proto::{
    op::{Message, Query},
    rr::{DNSClass, Name, RData, RecordType},
};

use crate::{
    config::{Config, LocalDnsAddr},
    context::{Context, SharedContext},
    relay::{
        loadbalancing::server::{ServerData, SharedServerStatistic},
        socks5::Address,
        sys::create_outbound_udp_socket,
        tcprelay::ProxyStream,
    },
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
        match config.local_dns_addr {
            Some(LocalDnsAddr::SocketAddr(ns)) => LocalUpstream::Udp(UdpUpstream { server: ns }),
            #[cfg(unix)]
            Some(LocalDnsAddr::UnixSocketAddr(ref p)) => {
                LocalUpstream::UnixSocket(UnixSocketUpstream { path: p.clone() })
            }
            None => panic!("LocalUpstream requires config.local_dns_addr"),
        }
    }

    pub async fn lookup(&self, context: &Context, query: &Query) -> io::Result<Message> {
        match self {
            LocalUpstream::Udp(upstream) => upstream.lookup(context, query).await,
            // LocalUpstream::Tcp(upstream) => upstream.lookup(query),
            #[cfg(unix)]
            LocalUpstream::UnixSocket(upstream) => upstream.lookup(context, query).await,
        }
    }

    pub async fn lookup_ip(&self, context: &Context, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let mut name = Name::from_utf8(host)?;
        name.set_fqdn(true);

        let mut queryv4 = Query::new();
        queryv4.set_query_class(DNSClass::IN);
        queryv4.set_name(name);

        let mut queryv6 = queryv4.clone();
        queryv4.set_query_type(RecordType::A);
        queryv6.set_query_type(RecordType::AAAA);

        let (responsev4, responsev6) =
            tokio::try_join!(self.lookup(context, &queryv4), self.lookup(context, &queryv6))?;

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
    async fn lookup(&self, context: &Context, query: &Query) -> io::Result<Message>;
}

fn generate_query_message(query: &Query) -> Message {
    let mut message = Message::new();
    message.set_id(rand::thread_rng().gen());
    message.set_recursion_desired(true);
    message.add_query(query.clone());
    message
}

pub async fn read_message<T: AsyncReadExt + Unpin>(stream: &mut T) -> io::Result<Message> {
    let mut res_buffer = [0; 2];
    stream.read_exact(&mut res_buffer).await?;

    let size = BigEndian::read_u16(&res_buffer) as usize;
    let mut res_buffer = vec![0; size];
    stream.read_exact(&mut res_buffer).await?;

    Ok(Message::from_vec(&res_buffer)?)
}

pub async fn write_message<T: AsyncWriteExt + Unpin>(stream: &mut T, message: &Message) -> io::Result<()> {
    let req_buffer = message.to_vec()?;
    let size = req_buffer.len();

    let mut send_buffer = BytesMut::with_capacity(2 + size);
    send_buffer.put_u16(size as u16);
    send_buffer.put_slice(&req_buffer);

    stream.write_all(&send_buffer).await
}

async fn stream_lookup<T>(query: &Query, stream: &mut T) -> io::Result<Message>
where
    T: AsyncReadExt + AsyncWriteExt + Unpin,
{
    write_message(stream, &generate_query_message(query)).await?;
    read_message(stream).await
}

pub struct UdpUpstream {
    pub server: SocketAddr,
}

impl Debug for UdpUpstream {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpUpstream").field("ns", &self.server).finish()
    }
}

#[async_trait]
impl Upstream for UdpUpstream {
    async fn lookup(&self, context: &Context, query: &Query) -> io::Result<Message> {
        // TODO: Reuse UdpSocket for sending queries

        trace!("DNS local query {:?} to {}", query, self.server);

        let local_addr = SocketAddr::new(
            match self.server {
                SocketAddr::V4(..) => IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                SocketAddr::V6(..) => IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
            },
            0,
        );
        let socket = create_outbound_udp_socket(&local_addr, context.config()).await?;

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

pub struct ProxyTcpUpstream<F, S>
where
    S: ServerData,
{
    context: SharedContext,
    svr_cfg: F,
    ns: Address,
    _s: PhantomData<S>,
}

impl<F, S> ProxyTcpUpstream<F, S>
where
    S: ServerData,
    F: Fn() -> SharedServerStatistic<S> + Send + Sync,
{
    pub fn new(context: SharedContext, svr_cfg: F, ns: Address) -> ProxyTcpUpstream<F, S> {
        ProxyTcpUpstream {
            context,
            svr_cfg,
            ns,
            _s: PhantomData,
        }
    }
}

impl<F, S> Debug for ProxyTcpUpstream<F, S>
where
    S: ServerData,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyTcpUpstream").field("ns", &self.ns).finish()
    }
}

#[async_trait]
impl<F, S> Upstream for ProxyTcpUpstream<F, S>
where
    S: ServerData,
    F: Fn() -> SharedServerStatistic<S> + Send + Sync,
{
    async fn lookup(&self, _context: &Context, query: &Query) -> io::Result<Message> {
        let svr_data = (self.svr_cfg)();
        let svr_cfg = svr_data.server_config();
        trace!("DNS proxied query {:?} via {} to {}", query, svr_cfg.addr(), self.ns);
        let mut stream = ProxyStream::connect_proxied(self.context.clone(), &svr_cfg, &self.ns).await?;
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
    async fn lookup(&self, _context: &Context, query: &Query) -> io::Result<Message> {
        let mut stream = UnixStream::connect(&self.path).await?;
        stream_lookup(query, &mut stream).await
    }
}
