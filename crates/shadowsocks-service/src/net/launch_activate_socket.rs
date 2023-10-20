//! macOS launch activate socket
//!
//! <https://developer.apple.com/documentation/xpc/1505523-launch_activate_socket>
//! <https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html>

use std::{
    io,
    net::{TcpListener, UdpSocket},
    os::unix::io::FromRawFd,
};

use crate::sys::get_launch_activate_socket;

pub fn get_launch_activate_tcp_listener(name: &str) -> io::Result<TcpListener> {
    let fd = get_launch_activate_socket(name)?;
    Ok(unsafe { TcpListener::from_raw_fd(fd) })
}

pub fn get_launch_activate_udp_socket(name: &str) -> io::Result<UdpSocket> {
    let fd = get_launch_activate_socket(name)?;
    Ok(unsafe { UdpSocket::from_raw_fd(fd) })
}
