use std::io;

use cfg_if::cfg_if;
use socket2::Socket;

cfg_if! {
    if #[cfg(unix)] {
        mod unix;
        #[allow(unused_imports)]
        pub use self::unix::*;
    }
}

#[cfg(unix)]
pub fn set_ipv6_only<S>(socket: &S, ipv6_only: bool) -> io::Result<()>
where
    S: std::os::unix::io::AsRawFd,
{
    use std::os::unix::io::{FromRawFd, IntoRawFd};

    let fd = socket.as_raw_fd();
    let sock = unsafe { Socket::from_raw_fd(fd) };
    let result = sock.set_only_v6(ipv6_only);
    let _ = sock.into_raw_fd();
    result
}

#[cfg(windows)]
#[allow(dead_code)]
pub fn set_ipv6_only<S>(socket: &S, ipv6_only: bool) -> io::Result<()>
where
    S: std::os::windows::io::AsRawSocket,
{
    use std::os::windows::io::{FromRawSocket, IntoRawSocket};

    let handle = socket.as_raw_socket();
    let sock = unsafe { Socket::from_raw_socket(handle) };
    let result = sock.set_only_v6(ipv6_only);
    let _ = sock.into_raw_socket();
    result
}
