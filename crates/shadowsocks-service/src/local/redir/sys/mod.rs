use std::io;

use cfg_if::cfg_if;
use socket2::SockRef;

cfg_if! {
    if #[cfg(unix)] {
        mod unix;
        #[allow(unused_imports)]
        pub use self::unix::*;
    }
}

#[cfg(unix)]
#[allow(dead_code)]
pub fn set_ipv6_only<S>(socket: &S, ipv6_only: bool) -> io::Result<()>
where
    S: std::os::unix::io::AsFd,
{
    let sock = SockRef::from(socket);
    sock.set_only_v6(ipv6_only)
}

#[cfg(windows)]
#[allow(dead_code)]
pub fn set_ipv6_only<S>(socket: &S, ipv6_only: bool) -> io::Result<()>
where
    S: std::os::windows::io::AsSocket,
{
    let sock = SockRef::from(socket);
    sock.set_only_v6(ipv6_only)
}
