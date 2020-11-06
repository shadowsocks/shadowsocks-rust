use std::{
    io::{self, Error, ErrorKind},
    mem,
    net::SocketAddr,
    os::unix::io::AsRawFd,
};

use async_trait::async_trait;
use tokio::net::{TcpListener, TcpSocket, TcpStream};

use crate::{
    config::RedirType,
    relay::{
        redir::{TcpListenerRedirExt, TcpStreamRedirExt},
        sys::sockaddr_to_std,
    },
};

#[async_trait]
impl TcpListenerRedirExt for TcpListener {
    async fn bind_redir(ty: RedirType, addr: &SocketAddr) -> io::Result<TcpListener> {
        match ty {
            RedirType::Redirect => {
                // REDIRECT rule doesn't need to set IP_TRANSPARENT
                TcpListener::bind(addr).await
            }
            RedirType::TProxy => {
                // TPROXY rule requires IP_TRANSPARENT
                create_redir_listener(addr)
            }
            _ => Err(Error::new(
                ErrorKind::InvalidInput,
                "not supported tcp transparent proxy type",
            )),
        }
    }
}

impl TcpStreamRedirExt for TcpStream {
    fn destination_addr(&self, ty: RedirType) -> io::Result<SocketAddr> {
        match ty {
            RedirType::Redirect => get_original_destination_addr(self),
            RedirType::TProxy => {
                // For TPROXY, uses getsockname() to retrieve original destination address
                self.local_addr()
            }
            _ => unreachable!("not supported tcp transparent proxy type"),
        }
    }
}

fn get_original_destination_addr(s: &TcpStream) -> io::Result<SocketAddr> {
    let fd = s.as_raw_fd();

    unsafe {
        let mut target_addr: libc::sockaddr_storage = mem::zeroed();
        let mut target_addr_len = mem::size_of_val(&target_addr) as libc::socklen_t;

        match s.local_addr()? {
            SocketAddr::V4(..) => {
                let ret = libc::getsockopt(
                    fd,
                    libc::SOL_IP,
                    libc::SO_ORIGINAL_DST,
                    &mut target_addr as *mut _ as *mut _,
                    &mut target_addr_len,
                );
                if ret != 0 {
                    let err = Error::last_os_error();
                    return Err(err);
                }
            }
            SocketAddr::V6(..) => {
                let ret = libc::getsockopt(
                    fd,
                    libc::SOL_IPV6,
                    libc::IP6T_SO_ORIGINAL_DST,
                    &mut target_addr as *mut _ as *mut _,
                    &mut target_addr_len,
                );

                if ret != 0 {
                    let err = Error::last_os_error();
                    return Err(err);
                }
            }
        }

        // Convert sockaddr_storage to SocketAddr
        sockaddr_to_std(&target_addr)
    }
}

fn create_redir_listener(addr: &SocketAddr) -> io::Result<TcpListener> {
    let socket = match *addr {
        SocketAddr::V4(..) => TcpSocket::new_v4(),
        SocketAddr::V6(..) => TcpSocket::new_v6(),
    };

    // For Linux 2.4+ TPROXY
    // Sockets have to set IP_TRANSPARENT, IPV6_TRANSPARENT for retrieving original destination by getsockname()
    unsafe {
        let fd = socket.as_raw_fd();

        let enable: libc::c_int = 1;
        let ret = match *addr {
            SocketAddr::V4(..) => libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_TRANSPARENT,
                &enable as *const _ as *const _,
                mem::size_of_val(&enable) as libc::socklen_t,
            ),
            SocketAddr::V6(..) => libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_TRANSPARENT,
                &enable as *const _ as *const _,
                mem::size_of_val(&enable) as libc::socklen_t,
            ),
        };

        if ret != 0 {
            return Err(Error::last_os_error());
        }
    }

    // tokio requires allow reuse addr
    socket.set_reuseaddr(true)?;

    // bind, listen as original
    socket.bind(addr)?;
    // listen backlogs = 1024 as mio's default
    socket.listen(1024).await
}
