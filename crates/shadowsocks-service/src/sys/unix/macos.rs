//! macOS specific APIs

use std::{ffi::CString, io, os::fd::RawFd, ptr};

use log::error;

unsafe extern "C" {
    /// https://developer.apple.com/documentation/xpc/1505523-launch_activate_socket
    fn launch_activate_socket(
        name: *const libc::c_char,
        fds: *mut *mut libc::c_int,
        cnt: *mut libc::size_t,
    ) -> libc::c_int;
}

pub fn get_launch_activate_socket(name: &str) -> io::Result<RawFd> {
    let mut fds: *mut libc::c_int = ptr::null_mut();
    let mut cnt: libc::size_t = 0;

    let cname = match CString::new(name) {
        Ok(n) => n,
        Err(..) => {
            return Err(io::Error::other(format!(
                "activate socket name \"{}\" contains NUL bytes",
                name
            )));
        }
    };

    unsafe {
        let ret = launch_activate_socket(cname.as_ptr(), &mut fds as *mut _, &mut cnt as *mut _);
        if ret != 0 {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::ENOENT) => {
                    error!("activate socket name \"{}\" doesn't exist, error: {}", name, err);
                }
                Some(libc::ESRCH) => {
                    error!("current process is not managed by launchd, error: {}", err);
                }
                Some(libc::EALREADY) => {
                    error!(
                        "activate socket name \"{}\" has already been activated, error: {}",
                        name, err
                    );
                }
                _ => {}
            }

            return Err(err);
        }
    }

    let result = if cnt == 0 {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("launch socket with name \"{}\" doesn't exist", name),
        ))
    } else if cnt > 1 {
        for idx in 0..cnt {
            unsafe {
                let fd = *(fds.add(idx));
                let _ = libc::close(fd);
            }
        }

        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "launch socket with name \"{}\" should be unique, but found {}",
                name, cnt
            ),
        ))
    } else {
        // Take fds[0] as the result
        let fd = unsafe { *fds };
        Ok(fd as RawFd)
    };

    if !fds.is_null() {
        unsafe { libc::free(fds as *mut _) };
    }

    result
}
