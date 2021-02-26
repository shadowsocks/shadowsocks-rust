use std::{
    io::{self, Error, ErrorKind},
    mem,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
};

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

#[allow(dead_code)]
#[cfg(not(target_os = "android"))]
pub fn set_nofile(nofile: u64) -> io::Result<()> {
    unsafe {
        // set both soft and hard limit
        let lim = libc::rlimit {
            rlim_cur: nofile as libc::rlim_t,
            rlim_max: nofile as libc::rlim_t,
        };

        if libc::setrlimit(libc::RLIMIT_NOFILE, &lim as *const _) < 0 {
            return Err(Error::last_os_error());
        }
    }

    Ok(())
}

#[allow(dead_code)]
#[cfg(target_os = "android")]
pub fn set_nofile(_nofile: u64) -> io::Result<()> {
    // Android doesn't have this API
    Ok(())
}
