//! Android specific features

use std::{
    convert::TryInto,
    io::{self, Error, ErrorKind, Read, Write},
    mem::{self, MaybeUninit},
    net::Shutdown,
    os::unix::io::{AsRawFd, RawFd},
    path::Path,
    pin::Pin,
    ptr,
    slice,
    task::{Context, Poll},
};

use futures::{future, ready};
use mio_uds::UnixStream as MioUnixStream;
use tokio::io::{AsyncRead, AsyncWrite, PollEvented};

/// A UnixStream supports transferring FDs between processes
pub struct UnixStream {
    io: PollEvented<MioUnixStream>,
}

impl UnixStream {
    /// Connects to the socket named by `path`.
    pub async fn connect<P: AsRef<Path>>(path: P) -> io::Result<UnixStream> {
        let uds = MioUnixStream::connect(path)?;
        let io = PollEvented::new(uds)?;

        future::poll_fn(|cx| io.poll_write_ready(cx)).await?;
        Ok(UnixStream { io })
    }

    fn poll_send_with_fd(&self, cx: &mut Context, buf: &[u8], fds: &[RawFd]) -> Poll<io::Result<usize>> {
        ready!(self.io.poll_write_ready(cx))?;

        let fd = self.io.get_ref().as_raw_fd();
        match send_with_fd(fd, buf, fds) {
            Err(ref err) if err.kind() == ErrorKind::WouldBlock => Poll::Pending,
            x => Poll::Ready(x),
        }
    }

    /// Send data with file descriptors
    pub async fn send_with_fd(&mut self, buf: &[u8], fds: &[RawFd]) -> io::Result<usize> {
        future::poll_fn(|cx| self.poll_send_with_fd(cx, buf, fds)).await
    }

    /// Shuts down the read, write, or both halves of this connection.
    ///
    /// This function will cause all pending and future I/O calls on the
    /// specified portions to immediately return with an appropriate value
    /// (see the documentation of `Shutdown`).
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.io.get_ref().shutdown(how)
    }
}

impl AsyncRead for UnixStream {
    unsafe fn prepare_uninitialized_buffer(&self, _: &mut [MaybeUninit<u8>]) -> bool {
        false
    }

    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        self.poll_read_priv(cx, buf)
    }
}

impl AsyncWrite for UnixStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.poll_write_priv(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shutdown(Shutdown::Write)?;
        Poll::Ready(Ok(()))
    }
}

impl UnixStream {
    // == Poll IO functions that takes `&self` ==
    //
    // They are not public because (taken from the doc of `PollEvented`):
    //
    // While `PollEvented` is `Sync` (if the underlying I/O type is `Sync`), the
    // caller must ensure that there are at most two tasks that use a
    // `PollEvented` instance concurrently. One for reading and one for writing.
    // While violating this requirement is "safe" from a Rust memory model point
    // of view, it will result in unexpected behavior in the form of lost
    // notifications and tasks hanging.

    pub(crate) fn poll_read_priv(&self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        ready!(self.io.poll_read_ready(cx, mio::Ready::readable()))?;

        match self.io.get_ref().read(buf) {
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.io.clear_read_ready(cx, mio::Ready::readable())?;
                Poll::Pending
            }
            x => Poll::Ready(x),
        }
    }

    pub(crate) fn poll_write_priv(&self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        ready!(self.io.poll_write_ready(cx))?;

        match self.io.get_ref().write(buf) {
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.io.clear_write_ready(cx)?;
                Poll::Pending
            }
            x => Poll::Ready(x),
        }
    }
}

/// A common implementation of `sendmsg` that sends provided bytes with ancillary file descriptors
/// over either a datagram or stream unix socket.
///
/// Borrowed from: https://github.com/Standard-Cognition/sendfd
fn send_with_fd(socket: RawFd, bs: &[u8], fds: &[RawFd]) -> io::Result<usize> {
    unsafe {
        let mut iov = libc::iovec {
            // NB: this casts *const to *mut, and in doing so we trust the OS to be a good citizen
            // and not mutate our buffer. This is the API we have to live with.
            iov_base: bs.as_ptr() as *const _ as *mut _,
            iov_len: bs.len(),
        };

        // Construct msghdr
        //
        // 1. Allocate memory for msg_control
        let cmsg_fd_len = fds.len() * mem::size_of::<RawFd>();
        let cmsg_buffer_len = libc::CMSG_SPACE(cmsg_fd_len as u32) as usize;
        let mut cmsg_buffer = Vec::with_capacity(cmsg_buffer_len);
        cmsg_buffer.set_len(cmsg_buffer_len);

        let mut msghdr = libc::msghdr {
            msg_name: ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iov as *mut _,
            msg_iovlen: 1,
            msg_control: cmsg_buffer.as_mut_ptr(),
            msg_controllen: cmsg_buffer_len.try_into().unwrap(),
            ..mem::zeroed()
        };

        // Fill cmsg with the file descriptors we are sending.
        let cmsg_header = libc::CMSG_FIRSTHDR(&mut msghdr as *mut _);
        cmsg_header.write(libc::cmsghdr {
            cmsg_level: libc::SOL_SOCKET,
            cmsg_type: libc::SCM_RIGHTS,
            cmsg_len: libc::CMSG_LEN(cmsg_fd_len as u32).try_into().unwrap(),
        });

        let cmsg_data = libc::CMSG_DATA(cmsg_header);
        let cmsg_data_slice = slice::from_raw_parts_mut(cmsg_data as *mut RawFd, fds.len());
        cmsg_data_slice.copy_from_slice(fds);

        let count = libc::sendmsg(socket, &msghdr as *const _, 0);
        if count < 0 {
            let err = Error::last_os_error();
            Err(err)
        } else {
            Ok(count as usize)
        }
    }
}
