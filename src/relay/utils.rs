use std::{
    future::Future,
    io::{self, Error},
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

#[cfg(all(unix, not(target_os = "android")))]
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

#[cfg(any(not(unix), target_os = "android"))]
pub fn set_nofile(_nofile: u64) -> io::Result<()> {
    // set_rlimit only works on *nix systems
    //
    // Windows' limit of opening files is the size of HANDLE (32-bits), so it is unlimited
    Ok(())
}
