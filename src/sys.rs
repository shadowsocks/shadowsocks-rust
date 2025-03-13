//! System related APIs

/// Some systems set an artificially low soft limit on open file count, for compatibility
/// with code that uses select and its hard-coded maximum file descriptor
/// (limited by the size of fd_set).
///
/// Tokio (Mio) doesn't use select.
///
/// http://0pointer.net/blog/file-descriptor-limits.html
/// https://github.com/golang/go/issues/46279
#[cfg(all(unix, not(target_os = "android")))]
pub fn adjust_nofile() {
    use log::{debug, trace};
    use std::{io::Error, mem};

    unsafe {
        let mut lim: libc::rlimit = mem::zeroed();
        let ret = libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim);
        if ret < 0 {
            debug!("getrlimit NOFILE failed, {}", Error::last_os_error());
            return;
        }

        if lim.rlim_cur != lim.rlim_max {
            trace!("rlimit NOFILE {:?} require adjustion", lim);
            lim.rlim_cur = lim.rlim_max;

            // On older macOS, setrlimit with rlim_cur = infinity will fail.
            #[cfg(any(target_os = "macos", target_os = "ios", target_os = "watchos", target_os = "tvos"))]
            {
                use std::ptr;

                unsafe extern "C" {
                    fn sysctlbyname(
                        name: *const libc::c_char,
                        oldp: *mut libc::c_void,
                        oldlenp: *mut libc::size_t,
                        newp: *mut libc::c_void,
                        newlen: libc::size_t,
                    ) -> libc::c_int;
                }

                // CTL_KERN
                //
                // Name                         Type                    Changeable
                // kern.maxfiles                int32_t                 yes
                // kern.maxfilesperproc         int32_t                 yes

                let name = b"kern.maxfilesperproc\0";
                let mut nfile: i32 = 0;
                let mut nfile_len: libc::size_t = mem::size_of_val(&nfile);

                let ret = sysctlbyname(
                    name.as_ptr() as *const _,
                    &mut nfile as *mut _ as *mut _,
                    &mut nfile_len,
                    ptr::null_mut(),
                    0,
                );

                if ret < 0 {
                    debug!("sysctlbyname kern.maxfilesperproc failed, {}", Error::last_os_error());
                } else {
                    lim.rlim_cur = nfile as libc::rlim_t;
                }
            }

            let ret = libc::setrlimit(libc::RLIMIT_NOFILE, &lim);
            if ret < 0 {
                debug!("setrlimit NOFILE {:?} failed, {}", lim, Error::last_os_error());
            } else {
                debug!("rlimit NOFILE adjusted {:?}", lim);
            }
        }
    }
}

/// setuid(), setgid() for a specific user or uid
#[cfg(unix)]
pub fn run_as_user(uname: &str) -> std::io::Result<()> {
    use log::error;
    use std::{
        ffi::{CStr, CString},
        io::{Error, ErrorKind},
    };

    unsafe {
        let pwd = match uname.parse::<libc::uid_t>() {
            Ok(uid) => {
                let mut pwd = libc::getpwuid(uid);
                if pwd.is_null() {
                    let uname = CString::new(uname).expect("username");
                    pwd = libc::getpwnam(uname.as_ptr())
                }
                pwd
            }
            Err(..) => {
                let uname = CString::new(uname).expect("username");
                libc::getpwnam(uname.as_ptr())
            }
        };

        if pwd.is_null() {
            return Err(Error::new(ErrorKind::InvalidInput, format!("user {} not found", uname)));
        }

        let pwd = &*pwd;

        // setgid first, because we may not allowed to do it anymore after setuid
        if libc::setgid(pwd.pw_gid as libc::gid_t) != 0 {
            let err = Error::last_os_error();

            error!(
                "could not change group id to user {:?}'s gid: {}, uid: {}, error: {}",
                CStr::from_ptr(pwd.pw_name),
                pwd.pw_gid,
                pwd.pw_uid,
                err
            );
            return Err(err);
        }

        if libc::initgroups(pwd.pw_name, pwd.pw_gid as _) != 0 {
            let err = Error::last_os_error();
            error!(
                "could not change supplementary groups to user {:?}'s gid: {}, uid: {}, error: {}",
                CStr::from_ptr(pwd.pw_name),
                pwd.pw_gid,
                pwd.pw_uid,
                err
            );
            return Err(err);
        }

        if libc::setuid(pwd.pw_uid) != 0 {
            let err = Error::last_os_error();
            error!(
                "could not change user id to user {:?}'s gid: {}, uid: {}, error: {}",
                CStr::from_ptr(pwd.pw_name),
                pwd.pw_gid,
                pwd.pw_uid,
                err
            );
            return Err(err);
        }
    }

    Ok(())
}
