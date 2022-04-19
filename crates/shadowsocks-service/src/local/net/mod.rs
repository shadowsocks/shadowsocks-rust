//! Shadowsocks Local Network Utilities

pub use self::{
    tcp::{auto_proxy_io::AutoProxyIo, auto_proxy_stream::AutoProxyClientStream},
    udp::{UdpAssociationManager, UdpInboundWrite},
};

mod tcp;
pub(crate) mod udp;
