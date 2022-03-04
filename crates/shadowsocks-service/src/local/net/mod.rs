//! Shadowsocks Local Network Utilities

pub use self::{
    tcp::{auto_proxy_io::AutoProxyIo, auto_proxy_stream::AutoProxyClientStream},
    udp::{
        UdpAssociationManager,
        UdpInboundWrite,
        UDP_ASSOCIATION_KEEP_ALIVE_CHANNEL_SIZE,
        UDP_ASSOCIATION_SEND_CHANNEL_SIZE,
    },
};

mod tcp;
mod udp;
