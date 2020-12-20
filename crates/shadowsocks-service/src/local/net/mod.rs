//! Shadowsocks Local Network Utilities

pub use self::{auto_proxy_io::AutoProxyIo, auto_proxy_stream::AutoProxyClientStream};

mod auto_proxy_io;
mod auto_proxy_stream;
