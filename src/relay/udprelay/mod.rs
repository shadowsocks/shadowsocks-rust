//! Relay for UDP implementation
//!
//! ## ShadowSocks UDP protocol
//!
//! SOCKS5 UDP Request
//! ```ignore
//! +----+------+------+----------+----------+----------+
//! |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//! +----+------+------+----------+----------+----------+
//! | 2  |  1   |  1   | Variable |    2     | Variable |
//! +----+------+------+----------+----------+----------+
//! ```
//!
//! SOCKS5 UDP Response
//! ```ignore
//! +----+------+------+----------+----------+----------+
//! |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//! +----+------+------+----------+----------+----------+
//! | 2  |  1   |  1   | Variable |    2     | Variable |
//! +----+------+------+----------+----------+----------+
//! ```
//!
//! shadowsocks UDP Request (before encrypted)
//! ```ignore
//! +------+----------+----------+----------+
//! | ATYP | DST.ADDR | DST.PORT |   DATA   |
//! +------+----------+----------+----------+
//! |  1   | Variable |    2     | Variable |
//! +------+----------+----------+----------+
//! ```
//!
//! shadowsocks UDP Response (before encrypted)
//! ```ignore
//! +------+----------+----------+----------+
//! | ATYP | DST.ADDR | DST.PORT |   DATA   |
//! +------+----------+----------+----------+
//! |  1   | Variable |    2     | Variable |
//! +------+----------+----------+----------+
//! ```
//!
//! shadowsocks UDP Request and Response (after encrypted)
//! ```ignore
//! +-------+--------------+
//! |   IV  |    PAYLOAD   |
//! +-------+--------------+
//! | Fixed |   Variable   |
//! +-------+--------------+
//! ```

use std::time::Duration;

mod association;
pub mod client;
mod crypto_io;
pub mod local;
#[cfg(feature = "local-redir")]
mod redir;
#[cfg(feature = "local-redir")]
mod redir_local;
pub mod server;
mod socks5_local;
#[cfg(feature = "local-tunnel")]
mod tunnel_local;
mod utils;

/// The maximum UDP payload size (defined in the original shadowsocks Python)
///
/// *I cannot find any references about why clowwindy used this value as the maximum
/// Socks5 UDP ASSOCIATE packet size. The only thing I can find is
/// [here](http://support.microsoft.com/kb/822061/)*
pub const MAXIMUM_UDP_PAYLOAD_SIZE: usize = 65536;

/// Default association expire time
///
/// FIXME: It is very hard to decide how long this value should be.
/// For some usecases, clients may open a socket for sending just one packet,
/// which will eventually cause too many *useless* associations are kept in the server.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);
