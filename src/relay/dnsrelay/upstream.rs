#[cfg(unix)]
use std::path::PathBuf;
use std::{
    fmt,
    fmt::{Debug, Display, Formatter},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use futures::{future, future::Either};
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
    config::{Config, LocalDnsAddr, Mode, ServerConfig},
    context::{Context, SharedContext},
    relay::{
        loadbalancing::server::{PlainPingBalancer, ServerType},
        socks5::Address,
        sys::{create_outbound_udp_socket, tcp_stream_connect},
        tcprelay::ProxyStream,
        udprelay::client::ServerClient as UdpServerClient,
    },
};

#[derive(Debug)]
pub enum LocalUpstream {
    TcpAndUdp(TcpUpstream, UdpUpstream),
    #[cfg(unix)]
    UnixSocket(UnixSocketUpstream),
}

impl Display for LocalUpstream {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LocalUpstream::TcpAndUdp(ref t, ..) => write!(f, "tcp+udp://{}", t.server),
            #[cfg(unix)]
            LocalUpstream::UnixSocket(ref u) => write!(f, "unix://{}", u.path.display()),
        }
    }
}

impl LocalUpstream {
    pub fn new(config: &Config) -> LocalUpstream {
        match config.local_dns_addr {
            Some(LocalDnsAddr::SocketAddr(ns)) => {
                LocalUpstream::TcpAndUdp(TcpUpstream { server: ns }, UdpUpstream { server: ns })
            }
            #[cfg(unix)]
            Some(LocalDnsAddr::UnixSocketAddr(ref p)) => {
                LocalUpstream::UnixSocket(UnixSocketUpstream { path: p.clone() })
            }
            None => panic!("LocalUpstream requires config.local_dns_addr"),
        }
    }

    pub async fn lookup(&self, context: &Context, query: &Query) -> io::Result<Message> {
        match self {
            LocalUpstream::TcpAndUdp(tcp, udp) => {
                match future::select(tcp.lookup(context, query), udp.lookup(context, query)).await {
                    Either::Left((tcp_result, udp_fut)) => match tcp_result {
                        Ok(message) => Ok(message),
                        Err(err) => {
                            trace!(
                                "LocalUpstream {} TCP query failed, error: {}, continue with UDP query, {:?}",
                                err,
                                tcp.server,
                                query
                            );
                            udp_fut.await
                        }
                    },
                    Either::Right((udp_result, tcp_fut)) => match udp_result {
                        Ok(message) => Ok(message),
                        Err(err) => {
                            trace!(
                                "LocalUpstream {} UDP query failed, error: {}, continue with TCP query, {:?}",
                                err,
                                udp.server,
                                query
                            );
                            tcp_fut.await
                        }
                    },
                }
            }
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
pub trait Upstream {
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

        trace!("DNS local UDP query {:?} to {}", query, self.server);

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

#[derive(Debug)]
pub struct TcpUpstream {
    pub server: SocketAddr,
}

#[async_trait]
impl Upstream for TcpUpstream {
    async fn lookup(&self, context: &Context, query: &Query) -> io::Result<Message> {
        // TODO: Reuse UdpSocket for sending queries

        trace!("DNS local TCP query {:?} to {}", query, self.server);

        let mut stream = tcp_stream_connect(&self.server, context.config()).await?;
        stream_lookup(query, &mut stream).await
    }
}

enum ProxyUpstreamMode {
    TcpOnly {
        balancer: PlainPingBalancer,
    },
    UdpOnly {
        balancer: PlainPingBalancer,
    },
    TcpAndUdp {
        tcp_balancer: PlainPingBalancer,
        udp_balancer: PlainPingBalancer,
    },
}

impl Debug for ProxyUpstreamMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ProxyUpstreamMode::TcpOnly { .. } => f.write_str("TcpOnly"),
            ProxyUpstreamMode::UdpOnly { .. } => f.write_str("UdpOnly"),
            ProxyUpstreamMode::TcpAndUdp { .. } => f.write_str("TcpAndUdp"),
        }
    }
}

pub struct ProxyUpstream {
    context: SharedContext,
    ns: Address,
    mode: ProxyUpstreamMode,
}

impl ProxyUpstream {
    pub async fn new(context: SharedContext, ns: Address) -> ProxyUpstream {
        let mode = match context.config().mode {
            Mode::TcpOnly => ProxyUpstreamMode::TcpOnly {
                balancer: PlainPingBalancer::new(context.clone(), ServerType::Tcp).await,
            },
            Mode::UdpOnly => ProxyUpstreamMode::UdpOnly {
                balancer: PlainPingBalancer::new(context.clone(), ServerType::Udp).await,
            },
            Mode::TcpAndUdp => ProxyUpstreamMode::TcpAndUdp {
                tcp_balancer: PlainPingBalancer::new(context.clone(), ServerType::Tcp).await,
                udp_balancer: PlainPingBalancer::new(context.clone(), ServerType::Udp).await,
            },
        };

        ProxyUpstream { context, ns, mode }
    }

    async fn tcp_lookup(&self, svr_cfg: &ServerConfig, query: &Query) -> io::Result<Message> {
        trace!(
            "DNS TCP proxied query {:?} via {} to {}",
            query,
            svr_cfg.addr(),
            self.ns
        );
        let mut stream = ProxyStream::connect_proxied(self.context.clone(), svr_cfg, &self.ns).await?;
        stream_lookup(query, &mut stream).await
    }

    async fn udp_lookup(&self, svr_cfg: &ServerConfig, query: &Query) -> io::Result<Message> {
        let context = &self.context;

        trace!(
            "DNS UDP proxied query {:?} via {} to {}",
            query,
            svr_cfg.addr(),
            self.ns
        );

        let client = UdpServerClient::new(context, svr_cfg).await?;

        let message = generate_query_message(query);
        let send_buf = message.to_vec()?;

        client.send_to(context, &self.ns, &send_buf).await?;

        let (_, recv_buf) = client.recv_from(context).await?;
        Message::from_vec(&recv_buf).map_err(From::from)
    }
}

impl Debug for ProxyUpstream {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyUpstream").field("ns", &self.ns).finish()
    }
}

impl Display for ProxyUpstream {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.mode {
            ProxyUpstreamMode::TcpOnly { .. } => write!(f, "tcp://{}", self.ns),
            ProxyUpstreamMode::UdpOnly { .. } => write!(f, "udp://{}", self.ns),
            ProxyUpstreamMode::TcpAndUdp { .. } => write!(f, "tcp+udp://{}", self.ns),
        }
    }
}

#[async_trait]
impl Upstream for ProxyUpstream {
    async fn lookup(&self, _context: &Context, query: &Query) -> io::Result<Message> {
        match self.mode {
            ProxyUpstreamMode::TcpOnly { ref balancer } => {
                let svr_cfg = balancer.pick_server();
                self.tcp_lookup(svr_cfg.server_config(), query).await
            }
            ProxyUpstreamMode::UdpOnly { ref balancer } => {
                let svr_cfg = balancer.pick_server();
                self.udp_lookup(svr_cfg.server_config(), query).await
            }
            ProxyUpstreamMode::TcpAndUdp {
                ref tcp_balancer,
                ref udp_balancer,
            } => {
                let tcp_svr_cfg = tcp_balancer.pick_server();
                let tcp_fut = self.tcp_lookup(tcp_svr_cfg.server_config(), query);
                tokio::pin!(tcp_fut);

                let udp_svr_cfg = udp_balancer.pick_server();
                let udp_fut = self.udp_lookup(udp_svr_cfg.server_config(), query);
                tokio::pin!(udp_fut);

                match future::select(tcp_fut, udp_fut).await {
                    Either::Left((tcp_result, udp_fut)) => match tcp_result {
                        Ok(message) => {
                            trace!("ProxyUpstream {} TCP query answer, {:?}", self.ns, message);
                            Ok(message)
                        }
                        Err(err) => {
                            trace!(
                                "ProxyUpstream {} TCP query failed, error: {}, continue with UDP query, {:?}",
                                self.ns,
                                err,
                                query
                            );
                            udp_fut.await
                        }
                    },
                    Either::Right((udp_result, tcp_fut)) => match udp_result {
                        Ok(message) => {
                            trace!("ProxyUpstream {} UDP query answer, {:?}", self.ns, message);
                            Ok(message)
                        }
                        Err(err) => {
                            trace!(
                                "ProxyUpstream {} UDP query failed, error: {}, continue with TCP query, {:?}",
                                self.ns,
                                err,
                                query
                            );
                            tcp_fut.await
                        }
                    },
                }
            }
        }
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
