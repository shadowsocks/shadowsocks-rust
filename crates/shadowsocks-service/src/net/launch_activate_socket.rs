//! macOS launch activate socket
//!
//! <https://developer.apple.com/documentation/xpc/1505523-launch_activate_socket>
//! <https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html>

use std::{
    io,
    net::{TcpListener, UdpSocket},
    os::unix::io::FromRawFd,
};

use log::debug;

use crate::sys::get_launch_activate_socket;

/// Get a macOS launch active socket as a `TcpListener`
pub fn get_launch_activate_tcp_listener(name: &str, nonblock: bool) -> io::Result<TcpListener> {
    let fd = get_launch_activate_socket(name)?;
    debug!("created TCP listener from launch activate socket {}", fd);
    let listener = unsafe { TcpListener::from_raw_fd(fd) };
    if nonblock {
        listener.set_nonblocking(true)?;
    }
    Ok(listener)
}

/// Get a macOS launch activate socket as a `UdpSocket`
pub fn get_launch_activate_udp_socket(name: &str, nonblock: bool) -> io::Result<UdpSocket> {
    let fd = get_launch_activate_socket(name)?;
    debug!("created UDP socket from launch activate socket {}", fd);
    let socket = unsafe { UdpSocket::from_raw_fd(fd) };
    if nonblock {
        socket.set_nonblocking(true)?;
    }
    Ok(socket)
}
