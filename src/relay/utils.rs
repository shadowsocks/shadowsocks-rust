use std::{
    future::Future,
    io::{self, Error, ErrorKind},
    io::prelude::*,
    net::{SocketAddr, TcpStream},
    time::Duration,
    os::unix::io::{AsRawFd, RawFd},
    os::unix::net::UnixStream,
};

use log::{info};

use net2::*;
use sendfd::*;
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

#[cfg(all(unix, not(target_os="android")))]
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

#[cfg(any(not(unix), target_os="android"))]
pub fn set_nofile(_nofile: u64) -> io::Result<()> {
    // set_rlimit only works on *nix systems
    //
    // Windows' limit of opening files is the size of HANDLE (32-bits), so it is unlimited
    Ok(())
}

#[cfg(target_os="android")]
pub fn protect(protect_path: &Option<String>, fd: RawFd) -> io::Result<()> {
    // ignore if protect_path is not specified
    let path = match protect_path {
        Some(path) => path,
        None => return Ok(()),
    };

    // it's safe to use blocking socket here
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(Duration::new(1, 0))).expect("couldn't set read timeout");
    stream.set_write_timeout(Some(Duration::new(1, 0))).expect("couldn't set write timeout");

    // send fds
    let dummy: [u8; 1] = [1];
    let fds: [RawFd; 1] = [fd];
    stream.send_with_fd(&dummy, &fds)?;

    // receive the return value
    let mut response = [0; 1];
    stream.read(&mut response)?;

    if response[0] == 0xFF {
        return Err(Error::new(ErrorKind::Other, "protect() failed"));
    }

    Ok(())
}

#[cfg(not(target_os="android"))]
pub fn protect(protect_path: &Option<String>, fd: RawFd) -> io::Result<()> {
    Ok(())
}

// create a new TCP stream
pub fn new_tcp_stream(protect_path: &Option<String>, saddr: &SocketAddr) -> io::Result<TcpStream> {
    let builder = match saddr {
        SocketAddr::V4(_) => TcpBuilder::new_v4()?,
        SocketAddr::V6(_) => TcpBuilder::new_v6()?,
    };

    protect(protect_path, builder.as_raw_fd())?;

    builder.to_tcp_stream()
}
