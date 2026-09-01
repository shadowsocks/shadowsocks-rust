//! Shadowsocks Service Network Utilities

pub use self::{
    flow::FlowStat,
    mon_socket::MonProxySocket,
    mon_stream::MonProxyStream,
    outbound::{
        HttpProxyAuth, OutboundProxyClient, OutboundProxyDatagram, OutboundProxyHop, OutboundProxyKind,
        OutboundProxyStream, Socks5Auth, Socks5Negotiator, TcpDialer,
    },
};

pub mod flow;
pub mod http_stream;
#[cfg(target_os = "macos")]
pub mod launch_activate_socket;
pub mod mon_socket;
pub mod mon_stream;
pub mod outbound;
pub mod packet_window;
pub mod utils;

/// Packet size for all UDP associations' send queue
pub const UDP_ASSOCIATION_SEND_CHANNEL_SIZE: usize = 1024;

/// Keep-alive channel size for UDP associations' manager
pub const UDP_ASSOCIATION_KEEP_ALIVE_CHANNEL_SIZE: usize = 64;
