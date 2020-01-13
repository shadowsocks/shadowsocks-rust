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

#[cfg(unix)]
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

#[cfg(not(unix))]
pub fn set_nofile(nofile: u64) -> io::Result<()> {
    // set_rlimit only works on *nix systems
    Ok(())
}
