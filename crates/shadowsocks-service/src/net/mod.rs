//! Shadowsocks Service Network Utilities

pub use self::{flow::FlowStat, mon_socket::MonProxySocket, mon_stream::MonProxyStream};

pub mod flow;
pub mod mon_socket;
pub mod mon_stream;
pub mod packet_window;
pub mod utils;

/// Packet size for all UDP associations' send queue
///
/// This value is set by test result of `perf3` locally running 6.4Gbps bitrates with lost-rate lower than 0.5%
pub const UDP_ASSOCIATION_SEND_CHANNEL_SIZE: usize = 51200;

/// Keep-alive channel size for UDP associations' manager
pub const UDP_ASSOCIATION_KEEP_ALIVE_CHANNEL_SIZE: usize = 64;
