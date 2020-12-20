//! DNS relay configuration

#[cfg(unix)]
use std::path::PathBuf;
use std::{
    fmt::{self, Display},
    net::SocketAddr,
    str::FromStr,
};

/// Parse `NameServerAddr` error
#[derive(Debug)]
pub struct NameServerAddrError;

/// Address for Manager server
#[derive(Debug, Clone)]
pub enum NameServerAddr {
    /// IP address
    SocketAddr(SocketAddr),
    /// Unix socket path
    #[cfg(unix)]
    UnixSocketAddr(PathBuf),
}

impl FromStr for NameServerAddr {
    type Err = NameServerAddrError;

    fn from_str(s: &str) -> Result<NameServerAddr, NameServerAddrError> {
        match s.parse::<SocketAddr>() {
            Ok(socket_addr) => Ok(NameServerAddr::SocketAddr(socket_addr)),
            #[cfg(unix)]
            Err(..) => Ok(NameServerAddr::UnixSocketAddr(PathBuf::from(s))),
            #[cfg(not(unix))]
            Err(..) => Err(NameServerAddrError),
        }
    }
}

impl Display for NameServerAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            NameServerAddr::SocketAddr(ref saddr) => Display::fmt(saddr, f),
            #[cfg(unix)]
            NameServerAddr::UnixSocketAddr(ref path) => Display::fmt(&path.display(), f),
        }
    }
}

impl From<SocketAddr> for NameServerAddr {
    fn from(addr: SocketAddr) -> NameServerAddr {
        NameServerAddr::SocketAddr(addr)
    }
}

#[cfg(unix)]
impl From<PathBuf> for NameServerAddr {
    fn from(p: PathBuf) -> NameServerAddr {
        NameServerAddr::UnixSocketAddr(p)
    }
}

#[cfg(unix)]
impl From<&str> for NameServerAddr {
    fn from(p: &str) -> NameServerAddr {
        NameServerAddr::UnixSocketAddr(PathBuf::from(p))
    }
}
