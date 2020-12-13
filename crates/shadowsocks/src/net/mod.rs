//! Network wrappers for shadowsocks' specific requirements

pub use self::{connect_opt::ConnectOpts, tcp::TcpStream, udp::UdpSocket};

mod connect_opt;
pub mod tcp;
pub mod udp;
