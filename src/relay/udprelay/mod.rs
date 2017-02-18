//! Relay for UDP implementation
//!
//! ## ShadowSocks UDP protocol
//!
//! SOCKS5 UDP Request
//! +----+------+------+----------+----------+----------+
//! |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//! +----+------+------+----------+----------+----------+
//! | 2  |  1   |  1   | Variable |    2     | Variable |
//! +----+------+------+----------+----------+----------+
//!
//! SOCKS5 UDP Response
//! +----+------+------+----------+----------+----------+
//! |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//! +----+------+------+----------+----------+----------+
//! | 2  |  1   |  1   | Variable |    2     | Variable |
//! +----+------+------+----------+----------+----------+
//!
//! shadowsocks UDP Request (before encrypted)
//! +------+----------+----------+----------+
//! | ATYP | DST.ADDR | DST.PORT |   DATA   |
//! +------+----------+----------+----------+
//! |  1   | Variable |    2     | Variable |
//! +------+----------+----------+----------+
//!
//! shadowsocks UDP Response (before encrypted)
//! +------+----------+----------+----------+
//! | ATYP | DST.ADDR | DST.PORT |   DATA   |
//! +------+----------+----------+----------+
//! |  1   | Variable |    2     | Variable |
//! +------+----------+----------+----------+
//!
//! shadowsocks UDP Request and Response (after encrypted)
//! +-------+--------------+
//! |   IV  |    PAYLOAD   |
//! +-------+--------------+
//! | Fixed |   Variable   |
//! +-------+--------------+

use std::io;

use net2::UdpBuilder;

pub mod local;
pub mod server;

mod crypto_io;

/// The maximum UDP payload size (defined in the original shadowsocks Python)
///
/// *I cannot find any references about why clowwindy used this value as the maximum
/// Socks5 UDP ASSOCIATE packet size. The only thing I can find is
/// [here](http://support.microsoft.com/kb/822061/)*
pub const MAXIMUM_UDP_PAYLOAD_SIZE: usize = 65536;

/// Maximum associations to maintain
pub const MAXIMUM_ASSOCIATE_MAP_SIZE: usize = 65536;

#[cfg(unix)]
fn reuse_port(builder: &UdpBuilder) -> io::Result<&UdpBuilder> {
    use net2::unix::UnixUdpBuilderExt;
    builder.reuse_port(true)
}

#[cfg(windows)]
fn reuse_port(builder: &UdpBuilder) -> io::Result<&UdpBuilder> {
    Ok(builder)
}