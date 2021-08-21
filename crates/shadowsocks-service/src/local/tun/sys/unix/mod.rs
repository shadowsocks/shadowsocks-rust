use std::{
    io::{self, ErrorKind, Read, Write},
    os::unix::io::AsRawFd,
    pin::Pin,
    task::{Context, Poll},
};

use cfg_if::cfg_if;
use futures::ready;
use log::error;
use tokio::io::{unix::AsyncFd, AsyncRead, AsyncWrite, ReadBuf};
use tun::{platform::Device, Configuration};

cfg_if! {
    if #[cfg(any(target_os = "linux"))] {
        mod linux;
        pub use self::linux::*;
    } else if #[cfg(target_vendor = "apple")] {
        mod apple;
        pub use self::apple::*;
    } else if #[cfg(any(target_os = "freebsd", target_os = "openbsd"))] {
        mod bsd;
        pub use self::bsd::*;
    } else if #[cfg(target_os = "android")] {
        mod android;
        pub use self::android::*;
    }
}

pub struct AsyncDevice {
    io: AsyncFd<Device>,
}

impl AsyncDevice {
    pub fn create(config: &Configuration) -> io::Result<AsyncDevice> {
        let device = match tun::create(config) {
            Ok(d) => d,
            Err(err) => {
                error!("failed to create tun device, error: {:?}", err);
                return Err(io::Error::new(ErrorKind::Other, err));
            }
        };

        // Set non-blocking for `AsyncFd`
        unsafe {
            let fd = device.as_raw_fd();
            let ret = libc::fcntl(fd, libc::F_SETFL, libc::fcntl(fd, libc::F_GETFL) | libc::O_NONBLOCK);
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(AsyncDevice {
            io: AsyncFd::new(device)?,
        })
    }

    #[inline]
    pub fn get_ref(&self) -> &Device {
        self.io.get_ref()
    }
}

impl AsyncRead for AsyncDevice {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.io.poll_read_ready_mut(cx))?;

            let rbuf = buf.initialize_unfilled();
            match guard.try_io(|io| io.get_mut().read(rbuf)) {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Ok(()).into();
                }
                Ok(Err(err)) => return Err(err).into(),
                Err(..) => continue,
            }
        }
    }
}

impl AsyncWrite for AsyncDevice {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        loop {
            let mut guard = ready!(self.io.poll_write_ready_mut(cx))?;

            match guard.try_io(|io| io.get_mut().write(buf)) {
                Ok(r) => return r.into(),
                Err(..) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Ok(()).into()
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Ok(()).into()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        loop {
            let mut guard = ready!(self.io.poll_write_ready_mut(cx))?;

            match guard.try_io(|io| io.get_mut().write_vectored(bufs)) {
                Ok(r) => return r.into(),
                Err(..) => continue,
            }
        }
    }
}
