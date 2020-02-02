use std::{
    future::Future,
    io::{self, Error, ErrorKind},
    mem,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    time::Duration,
};

use tokio::time;

pub async fn try_timeout<T, E, F>(fut: F, timeout: Option<Duration>) -> io::Result<T>
where
    F: Future<Output = Result<T, E>>,
    Error: From<E>,
{
    match timeout {
        Some(t) => time::timeout(t, fut).await?,
        None => fut.await,
    }
    .map_err(From::from)
}

#[cfg(unix)]
pub fn set_nofile(nofile: u64) -> io::Result<()> {
    unsafe {
        // set both soft and hard limit
        let lim = libc::rlimit {
            rlim_cur: nofile,
            rlim_max: nofile,
        };

        if libc::setrlimit(libc::RLIMIT_NOFILE, &lim as *const _) < 0 {
            return Err(Error::last_os_error());
        }
    }

    Ok(())
}

#[cfg(not(unix))]
pub fn set_nofile(_nofile: u64) -> io::Result<()> {
    // set_rlimit only works on *nix systems
    Ok(())
}

/// Convert `sockaddr_storage` to `SocketAddr`
#[allow(dead_code)]
pub fn sockaddr_to_std(saddr: &libc::sockaddr_storage) -> io::Result<SocketAddr> {
    match saddr.ss_family as libc::c_int {
        libc::AF_INET => unsafe {
            let addr: SocketAddrV4 = mem::transmute_copy(saddr);
            Ok(SocketAddr::V4(addr))
        },
        libc::AF_INET6 => unsafe {
            let addr: SocketAddrV6 = mem::transmute_copy(saddr);
            Ok(SocketAddr::V6(addr))
        },
        _ => {
            let err = Error::new(ErrorKind::InvalidData, "family must be either AF_INET or AF_INET6");
            Err(err)
        }
    }
}
