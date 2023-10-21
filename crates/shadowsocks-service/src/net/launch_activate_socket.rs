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

pub fn get_launch_activate_tcp_listener(name: &str) -> io::Result<Option<TcpListener>> {
    match get_launch_activate_socket(name)? {
        Some(fd) => {
            debug!("created TCP listener from launch activate socket {}", fd);
            Ok(Some(unsafe { TcpListener::from_raw_fd(fd) }))
        }
        None => Ok(None),
    }
}

pub fn get_launch_activate_udp_socket(name: &str) -> io::Result<Option<UdpSocket>> {
    match get_launch_activate_socket(name)? {
        Some(fd) => {
            debug!("created UDP socket from launch activate socket {}", fd);
            Ok(Some(unsafe { UdpSocket::from_raw_fd(fd) }))
        }
        None => Ok(None),
    }
}
