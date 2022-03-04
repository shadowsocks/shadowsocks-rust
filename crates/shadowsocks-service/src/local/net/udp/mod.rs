pub use self::association::{UdpAssociationManager, UdpInboundWrite};

pub mod association;

/// Packet size for all UDP associations' send queue
pub static UDP_ASSOCIATION_SEND_CHANNEL_SIZE: usize = 8192;

/// Keep-alive channel size for UDP associations' manager
pub static UDP_ASSOCIATION_KEEP_ALIVE_CHANNEL_SIZE: usize = 256;
