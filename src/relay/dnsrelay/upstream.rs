use std::io::Result;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use trust_dns_proto::op::Message;

pub trait Upstream {
    async fn lookup(&self, request: &Message) -> Result<Message>;
}

struct UdpUpstream {
    server: SocketAddr,
}

impl Upstream for UdpUpstream {
    async fn lookup(&self, request: &Message) -> Result<Message> {
        let socket = UdpSocket::bind(SocketAddr::new(match *self.server {
            SocketAddr::V4(..) => IpAddr::v4(Ipv4Addr::new(0, 0, 0, 0)),
            SocketAddr::V6(..) => IpAddr::v6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
        }, 0)).await?;
        socket.send_to(&request.to_vec()?, self.server).await?;
        let mut response = vec![0; 512];
        socket.recv_from(&mut response).await?;
        Ok(Message::from_vec(&response)?)
    }
}

struct Socks5UdpUpstream {
    server: SocketAddr,
}

impl Upstream for Socks5UdpUpstream {
    async fn lookup(&self, request: &Message) -> Result<Message> {
        let socket = UdpSocket::bind(SocketAddr::new(IpAddr::v4(Ipv4Addr::new(0, 0, 0, 0)), 0)).await?;
        unimplemented!()
    }
}

struct TcpUpstream {
    server: SocketAddr,
}

impl Upstream for TcpUpstream {
    async fn lookup(&self, request: &Message) -> Result<Message> {
        unimplemented!()
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
struct UnixSocketUpstream {
    path: String,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl Upstream for UnixSocketUpstream {
    async fn lookup(&self, request: &Message) -> Result<Message> {
        use tokio::net::UnixStream;
        let socket = UnixStream::connect(path).await?;
        unimplemented!()
    }
}
