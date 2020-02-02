use std::{
    io::{self, Error},
    mem,
    net::SocketAddr,
    os::unix::io::AsRawFd,
};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::{TcpListener, TcpStream};

use crate::relay::sys::sockaddr_to_std;

pub fn check_support_tproxy() -> io::Result<()> {
    Ok(())
}

pub fn get_original_destination_addr(s: &mut TcpStream) -> io::Result<SocketAddr> {
    let fd = s.as_raw_fd();

    unsafe {
        let mut target_addr: libc::sockaddr_storage = mem::zeroed();
        let mut target_addr_len = mem::size_of_val(&target_addr) as libc::socklen_t;

        // Check if it is IPv6 address
        let ret = libc::getsockopt(
            fd,
            libc::SOL_IPV6,
            libc::SO_ORIGINAL_DST, // FIXME: Should use IP6T_SO_ORIGINAL_DST
            &mut target_addr as *mut _ as *mut _,
            &mut target_addr_len,
        );

        if ret != 0 {
            let err = Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::ENOPROTOOPT) | Some(libc::EOPNOTSUPP) => {
                    // The option is unknown at the level indicated.
                    //
                    // - The current system doesn't support IPv6 netfilter
                    // - This is not an IPv6 connection
                    //
                    // Continue with IPv4
                }
                _ => {
                    return Err(err);
                }
            }

            let ret = libc::getsockopt(
                fd,
                libc::SOL_IP,
                libc::SO_ORIGINAL_DST,
                &mut target_addr as *mut _ as *mut _,
                &mut target_addr_len,
            );
            if ret != 0 {
                let err = Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::ENOPROTOOPT) | Some(libc::EOPNOTSUPP) => {
                        // The option is unknown at the level indicated.
                        //
                        // - The current system doesn't support IPv4 netfilter (Linux 2.4-)
                        // - This is not a REDIRECT rule, maybe TPROXY
                        //
                        // Continue with getsockname()
                    }
                    _ => {
                        return Err(err);
                    }
                }

                // For TPROXY, uses getsockname() to retrieve original destination address
                return s.local_addr();
            }
        }

        // Convert sockaddr_storage to SocketAddr
        sockaddr_to_std(&target_addr)
    }
}

pub async fn create_redir_listener(addr: &SocketAddr) -> io::Result<TcpListener> {
    let domain = match *addr {
        SocketAddr::V4(..) => Domain::ipv4(),
        SocketAddr::V6(..) => Domain::ipv6(),
    };

    let socket = Socket::new(domain, Type::stream(), Some(Protocol::tcp()))?;

    // For Linux 2.4+ TPROXY
    // Sockets have to set IP_TRANSPARENT for retrieving original destination by getsockname()
    unsafe {
        let fd = socket.as_raw_fd();

        let enable: libc::c_int = 1;
        let ret = match *addr {
            SocketAddr::V4(..) => libc::setsockopt(
                fd,
                libc::SOL_IP,
                libc::IP_TRANSPARENT,
                &enable as *const _ as *const _,
                mem::size_of_val(&enable) as libc::socklen_t,
            ),
            SocketAddr::V6(..) => libc::setsockopt(
                fd,
                libc::SOL_IPV6,
                libc::IP_TRANSPARENT,
                &enable as *const _ as *const _,
                mem::size_of_val(&enable) as libc::socklen_t,
            ),
        };

        if ret != 0 {
            return Err(Error::last_os_error());
        }
    }

    // tokio requires non-blocked socket, and allow reuse addr
    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;

    let addr = SockAddr::from(*addr);

    // bind, listen as original
    socket.bind(&addr)?;
    socket.listen(1024)?; // backlogs = 1024 as mio's default

    TcpListener::from_std(socket.into_tcp_listener())
}
