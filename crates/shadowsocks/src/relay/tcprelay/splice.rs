//! Zero-copy relay between two TCP sockets with `splice(2)`
//!
//! The bytes of the `none` cipher are the bytes of the application, so a relay between two sockets
//! does not have to look at them. [`copy_bidirectional_splice`] moves them through a pipe in the
//! kernel instead of reading them into a userspace buffer and writing them out again.
//!
//! The semantics follow [`tokio::io::copy_bidirectional`]: when a side reaches EOF, the other side is
//! shut down for writing and the opposite direction keeps running until it ends too.
//!
//! Readiness is handled with [`TcpStream::try_io`], so an `EAGAIN` from `splice(2)` clears tokio's
//! readiness and the task sleeps until the socket is ready again.
//!
//! If the kernel refuses to splice (`EINVAL`, `ENOSYS`, `EOPNOTSUPP`) before the first successful
//! splice of a direction, that direction continues with a plain userspace copy. A failed `splice(2)`
//! consumes no data, and bytes already moved into the pipe are copied out before switching, so
//! nothing is lost.
//!
//! `splice(2)` from TCP stops in front of urgent data (`MSG_OOB`), and says `EAGAIN` there for as long
//! as nothing reads past it. The relay reads past it with `recv(2)`, which drops the urgent byte, as
//! the userspace copy does.
//!
//! `splice(2)` into a socket whose peer is gone raises `SIGPIPE`, as it can't take `MSG_NOSIGNAL`. The
//! Rust runtime ignores the signal in executables. Where it would end the process (a host process
//! written in another language may keep the default action), the relay copies through userspace.

use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
};

use futures::future::try_join;
use log::{debug, trace};
use tokio::{io::Interest, net::TcpStream};

/// Pipe capacity requested for each direction. It is best effort: unprivileged processes are
/// limited by `/proc/sys/fs/pipe-max-size` and by `pipe-user-pages-soft`.
///
/// A pipe holds what the destination hasn't taken yet, and an unprivileged user gets 64 MiB of pipes
/// by default (`pipe-user-pages-soft`): 128 connections spliced both ways at 256 KiB. Pipes of 1 MiB
/// save little CPU over 256 KiB ones, pipes of 64 KiB cost noticeably more.
const PIPE_CAPACITY: usize = 1 << 18;

/// A pipe smaller than this makes `splice(2)` slower than copying (the kernel hands out pipes of one
/// or two pages to users over their `pipe-user-pages-soft` budget), so such a direction copies instead.
const MIN_PIPE_CAPACITY: usize = 1 << 16;

/// Buffer size of the userspace fallback
const COPY_BUFFER_SIZE: usize = 1 << 16;

/// Observer of the bytes a relay moves through the socket `a`
///
/// `MonProxyStream` counts the bytes of a monitored socket when it reads from or writes to it; a
/// spliced relay never goes through the stream wrapper, so it reports them here instead.
pub trait SpliceMonitor: Sync {
    /// `n` bytes were read from the socket `a`
    fn read_a(&self, n: u64);

    /// `n` bytes were written to the socket `a`
    fn wrote_a(&self, n: u64);
}

impl SpliceMonitor for () {
    #[inline]
    fn read_a(&self, _: u64) {}

    #[inline]
    fn wrote_a(&self, _: u64) {}
}

/// The system calls, so that the failure paths can be tested
trait Syscalls: Sync {
    /// `splice(socket -> pipe)`
    fn splice_to_pipe(&self, socket: RawFd, pipe: RawFd, len: usize) -> io::Result<usize>;

    /// `splice(pipe -> socket)`
    fn splice_from_pipe(&self, pipe: RawFd, socket: RawFd, len: usize) -> io::Result<usize>;

    /// See [`sigpipe_is_harmless`]
    fn sigpipe_is_harmless(&self) -> bool;
}

struct Kernel;

fn splice(from: RawFd, to: RawFd, len: usize) -> io::Result<usize> {
    // SAFETY: both descriptors are open for the duration of the call, the offsets are null (the
    // descriptors are a socket and a pipe) and no memory is passed.
    let ret = unsafe {
        libc::splice(
            from,
            std::ptr::null_mut(),
            to,
            std::ptr::null_mut(),
            len,
            libc::SPLICE_F_NONBLOCK,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as usize)
    }
}

impl Syscalls for Kernel {
    #[inline]
    fn splice_to_pipe(&self, socket: RawFd, pipe: RawFd, len: usize) -> io::Result<usize> {
        splice(socket, pipe, len)
    }

    #[inline]
    fn splice_from_pipe(&self, pipe: RawFd, socket: RawFd, len: usize) -> io::Result<usize> {
        splice(pipe, socket, len)
    }

    #[inline]
    fn sigpipe_is_harmless(&self) -> bool {
        sigpipe_is_harmless()
    }
}

/// `false` if `SIGPIPE` would end the process
///
/// `splice(2)` has no `MSG_NOSIGNAL`: moving bytes into a socket whose peer is gone raises `SIGPIPE`.
/// The Rust runtime ignores it in executables, but a host process written in another language may
/// keep the default action, which terminates.
fn sigpipe_is_harmless() -> bool {
    let mut action = std::mem::MaybeUninit::<libc::sigaction>::uninit();
    // SAFETY: with a null new action, `sigaction` only writes the current one into `action`.
    unsafe {
        libc::sigaction(libc::SIGPIPE, std::ptr::null(), action.as_mut_ptr()) == 0
            && action.assume_init().sa_sigaction != libc::SIG_DFL
    }
}

/// `true` for the errors with which the kernel says "I can't splice this", as opposed to a failure
/// of the connection
fn is_unsupported(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP))
}

struct Pipe {
    reader: OwnedFd,
    writer: OwnedFd,
    capacity: usize,
}

impl Pipe {
    fn new() -> io::Result<Self> {
        let mut fds = [0; 2];
        // SAFETY: `fds` has room for the two descriptors `pipe2` writes.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `pipe2` succeeded, so both are open descriptors that nothing else owns.
        let (reader, writer) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };

        // SAFETY: plain `fcntl` calls on a descriptor that is open.
        let capacity = unsafe {
            let set = libc::fcntl(writer.as_raw_fd(), libc::F_SETPIPE_SZ, PIPE_CAPACITY as libc::c_int);
            if set > 0 {
                set
            } else {
                libc::fcntl(writer.as_raw_fd(), libc::F_GETPIPE_SZ)
            }
        };

        Ok(Self {
            reader,
            writer,
            capacity: capacity.max(0) as usize,
        })
    }

    /// Moves the `len` bytes left in the pipe to `dst` without `splice(2)`
    async fn drain_to(&self, mut len: usize, dst: &TcpStream, on_write: &impl Fn(u64)) -> io::Result<u64> {
        let mut buf = vec![0u8; len.min(COPY_BUFFER_SIZE)];
        let mut total = 0;
        while len > 0 {
            let want = len.min(buf.len());
            // SAFETY: `buf` is valid for `want` bytes and the reader is open.
            let n = unsafe { libc::read(self.reader.as_raw_fd(), buf.as_mut_ptr().cast(), want) };
            if n <= 0 {
                // The pipe holds the bytes of an earlier splice, so they can't be missing.
                return Err(if n < 0 {
                    io::Error::last_os_error()
                } else {
                    io::ErrorKind::UnexpectedEof.into()
                });
            }
            let n = n as usize;
            write_all(dst, &buf[..n], on_write).await?;
            len -= n;
            total += n as u64;
        }
        Ok(total)
    }
}

async fn write_all(dst: &TcpStream, mut buf: &[u8], on_write: &impl Fn(u64)) -> io::Result<()> {
    while !buf.is_empty() {
        dst.writable().await?;
        match dst.try_write(buf) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => {
                on_write(n as u64);
                buf = &buf[n..];
            }
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

fn shutdown_write(dst: &TcpStream) -> io::Result<()> {
    match socket2::SockRef::from(dst).shutdown(std::net::Shutdown::Write) {
        // The peer has reset the connection, or it timed out: there is nothing left to shut down,
        // which tokio's `TcpStream::poll_shutdown` takes as success too.
        Err(err) if err.kind() == io::ErrorKind::NotConnected => Ok(()),
        res => res,
    }
}

/// `true` if `recv(2)` would return bytes from `socket` right now
fn recv_has_data(socket: RawFd) -> io::Result<bool> {
    let mut byte = 0u8;
    // SAFETY: `byte` is valid for the one byte asked for, and the socket is open.
    let ret = unsafe { libc::recv(socket, (&raw mut byte).cast(), 1, libc::MSG_PEEK | libc::MSG_DONTWAIT) };
    if ret >= 0 {
        Ok(ret > 0)
    } else {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock {
            Ok(false)
        } else {
            Err(err)
        }
    }
}

/// `true` for a `splice(2)` that says EAGAIN or EOF
fn moved_nothing(res: &io::Result<usize>) -> bool {
    match *res {
        Ok(n) => n == 0,
        Err(ref err) => err.kind() == io::ErrorKind::WouldBlock,
    }
}

/// The result of a read step of the splice relay
enum Read {
    /// Bytes moved into the pipe, 0 at EOF
    Spliced(usize),
    /// `splice(2)` stopped in front of TCP urgent data, which only `recv(2)` goes past
    Urgent,
}

/// Copies `src` to `dst` through userspace, up to EOF of `src`, then shuts `dst` down for writing
async fn copy_direction(
    src: &TcpStream,
    dst: &TcpStream,
    on_read: &impl Fn(u64),
    on_write: &impl Fn(u64),
) -> io::Result<u64> {
    let mut buf = vec![0u8; COPY_BUFFER_SIZE].into_boxed_slice();
    let mut total = 0;
    loop {
        src.readable().await?;
        match src.try_read(&mut buf) {
            Ok(0) => {
                shutdown_write(dst)?;
                return Ok(total);
            }
            Ok(n) => {
                on_read(n as u64);
                write_all(dst, &buf[..n], on_write).await?;
                total += n as u64;
            }
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {}
            Err(err) => return Err(err),
        }
    }
}

/// One direction of the relay: from `src` to `dst`, up to EOF of `src`
///
/// `on_read` is called with the number of bytes taken out of `src`, `on_write` with the number of
/// bytes put into `dst`. Returns the number of bytes delivered to `dst`.
async fn relay_direction<S: Syscalls>(
    sys: &S,
    src: &TcpStream,
    dst: &TcpStream,
    on_read: impl Fn(u64),
    on_write: impl Fn(u64),
) -> io::Result<u64> {
    // Don't take a pipe for a connection that never sends anything in this direction.
    src.readable().await?;

    if !sys.sigpipe_is_harmless() {
        debug!("SIGPIPE is not ignored, copying");
        return copy_direction(src, dst, &on_read, &on_write).await;
    }

    let pipe = match Pipe::new() {
        Ok(pipe) if pipe.capacity >= MIN_PIPE_CAPACITY => pipe,
        Ok(pipe) => {
            debug!("pipe too small ({} bytes) for splice, copying", pipe.capacity);
            drop(pipe);
            return copy_direction(src, dst, &on_read, &on_write).await;
        }
        Err(err) => {
            debug!("can't create a pipe for splice, copying: {}", err);
            return copy_direction(src, dst, &on_read, &on_write).await;
        }
    };

    let (src_fd, dst_fd) = (src.as_raw_fd(), dst.as_raw_fd());
    let (pipe_r, pipe_w) = (pipe.reader.as_raw_fd(), pipe.writer.as_raw_fd());
    // MPTCP has no urgent data, and splices through `recvmsg`
    let tcp = matches!(socket2::SockRef::from(src).protocol(), Ok(Some(socket2::Protocol::TCP)));

    // Set after the first successful splice into `dst`. Before that, "unsupported" errors mean the
    // kernel can't splice this pair of sockets, and nothing has been lost by trying.
    let mut proven = false;
    let mut total = 0;

    loop {
        src.readable().await?;
        let read = src.try_io(Interest::READABLE, || {
            let res = sys.splice_to_pipe(src_fd, pipe_w, pipe.capacity);
            // Urgent data stops splice(2) with EAGAIN, or 0 once the FIN is in, until something reads
            // past it, while recv(2) sees the bytes behind it. Bytes that came in after the splice look
            // the same: splice again to tell. Past urgent data, the readiness has to stay, as no new
            // data may come to set it again.
            if tcp && moved_nothing(&res) && recv_has_data(src_fd)? {
                let again = sys.splice_to_pipe(src_fd, pipe_w, pipe.capacity);
                return if moved_nothing(&again) {
                    Ok(Read::Urgent)
                } else {
                    again.map(Read::Spliced)
                };
            }
            res.map(Read::Spliced)
        });
        let mut pending = match read {
            Ok(Read::Spliced(0)) => {
                // EOF, and the pipe has been drained by the previous iteration.
                shutdown_write(dst)?;
                return Ok(total);
            }
            Ok(Read::Spliced(n)) => n,
            Ok(Read::Urgent) => {
                // The pipe is empty: what `recv(2)` returns goes next. It drops the urgent byte,
                // unless the socket has SO_OOBINLINE, as the userspace copy does.
                let mut buf = vec![0u8; COPY_BUFFER_SIZE];
                match src.try_read(&mut buf) {
                    Ok(0) => {
                        shutdown_write(dst)?;
                        return Ok(total);
                    }
                    Ok(n) => {
                        on_read(n as u64);
                        write_all(dst, &buf[..n], &on_write).await?;
                        total += n as u64;
                    }
                    Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {}
                    Err(err) => return Err(err),
                }
                continue;
            }
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => continue,
            Err(ref err) if !proven && is_unsupported(err) => {
                debug!("splice from socket is not supported ({}), copying", err);
                drop(pipe);
                return Ok(total + copy_direction(src, dst, &on_read, &on_write).await?);
            }
            Err(err) => return Err(err),
        };
        on_read(pending as u64);

        while pending > 0 {
            dst.writable().await?;
            match dst.try_io(Interest::WRITABLE, || sys.splice_from_pipe(pipe_r, dst_fd, pending)) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => {
                    proven = true;
                    pending -= n;
                    total += n as u64;
                    on_write(n as u64);
                }
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(ref err) if !proven && is_unsupported(err) => {
                    debug!("splice to socket is not supported ({}), copying", err);
                    // `pending` bytes sit in the pipe: they go first.
                    total += pipe.drain_to(pending, dst, &on_write).await?;
                    drop(pipe);
                    return Ok(total + copy_direction(src, dst, &on_read, &on_write).await?);
                }
                Err(err) => return Err(err),
            }
        }
    }
}

async fn relay<S: Syscalls, M: SpliceMonitor>(
    sys: &S,
    a: &TcpStream,
    b: &TcpStream,
    monitor: &M,
) -> io::Result<(u64, u64)> {
    try_join(
        relay_direction(sys, a, b, |n| monitor.read_a(n), |_| {}),
        relay_direction(sys, b, a, |_| {}, |n| monitor.wrote_a(n)),
    )
    .await
}

/// Copies data in both directions between `a` and `b`, with `splice(2)`
///
/// If an EOF is observed on one stream, the other is shut down for writing and the opposite
/// direction keeps going. The future completes when both directions are done, with the number of
/// bytes copied from `a` to `b` and from `b` to `a`, or fails at the first I/O error, which may lose
/// bytes in flight, as [`tokio::io::copy_bidirectional`] does.
///
/// The caller must not have bytes buffered on its side of either socket.
pub async fn copy_bidirectional_splice(a: &TcpStream, b: &TcpStream) -> io::Result<(u64, u64)> {
    copy_bidirectional_splice_monitored(a, b, &()).await
}

/// Like [`copy_bidirectional_splice`], reporting the bytes that go through `a` to `monitor` as they
/// move
pub async fn copy_bidirectional_splice_monitored<M: SpliceMonitor>(
    a: &TcpStream,
    b: &TcpStream,
    monitor: &M,
) -> io::Result<(u64, u64)> {
    let res = relay(&Kernel, a, b, monitor).await;
    trace!("splice relay ends: {:?}", res);
    res
}

#[cfg(test)]
mod tests {
    use std::{
        net::SocketAddr,
        sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;

    /// Makes the `n`th (counting from 0) splice of each kind fail with an errno
    struct Faulty {
        to_pipe_errno: Option<i32>,
        from_pipe_errno: Option<i32>,
        /// Number of `splice_from_pipe` calls to let through before failing
        from_pipe_after: usize,
        from_pipe_calls: AtomicUsize,
    }

    impl Faulty {
        fn none() -> Self {
            Self {
                to_pipe_errno: None,
                from_pipe_errno: None,
                from_pipe_after: 0,
                from_pipe_calls: AtomicUsize::new(0),
            }
        }
    }

    impl Syscalls for Faulty {
        fn splice_to_pipe(&self, socket: RawFd, pipe: RawFd, len: usize) -> io::Result<usize> {
            match self.to_pipe_errno {
                Some(errno) => Err(io::Error::from_raw_os_error(errno)),
                None => Kernel.splice_to_pipe(socket, pipe, len),
            }
        }

        fn splice_from_pipe(&self, pipe: RawFd, socket: RawFd, len: usize) -> io::Result<usize> {
            let call = self.from_pipe_calls.fetch_add(1, Ordering::Relaxed);
            match self.from_pipe_errno {
                Some(errno) if call >= self.from_pipe_after => Err(io::Error::from_raw_os_error(errno)),
                _ => Kernel.splice_from_pipe(pipe, socket, len),
            }
        }

        fn sigpipe_is_harmless(&self) -> bool {
            Kernel.sigpipe_is_harmless()
        }
    }

    #[derive(Default)]
    struct Counters {
        read_a: AtomicU64,
        wrote_a: AtomicU64,
    }

    impl SpliceMonitor for Counters {
        fn read_a(&self, n: u64) {
            self.read_a.fetch_add(n, Ordering::Relaxed);
        }

        fn wrote_a(&self, n: u64) {
            self.wrote_a.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// A broken relay hangs instead of failing: put a deadline on everything
    async fn within<T>(fut: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(std::time::Duration::from_secs(60), fut)
            .await
            .expect("test timed out")
    }

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        (client.unwrap(), accepted.unwrap().0)
    }

    /// `x <-> [a  b] <-> y`: the relay forwards between `a` and `b`; the test talks to `x` and `y`.
    struct Rig {
        x: TcpStream,
        y: TcpStream,
        a: TcpStream,
        b: TcpStream,
    }

    async fn rig() -> Rig {
        let (x, a) = tcp_pair().await;
        let (b, y) = tcp_pair().await;
        Rig { x, y, a, b }
    }

    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| {
                (i as u8)
                    .wrapping_mul(31)
                    .wrapping_add((i >> 8) as u8)
                    .wrapping_add(seed)
            })
            .collect()
    }

    /// Sends `up` from x and `down` from y, each followed by a half-close, and checks both arrive
    /// whole and that each side sees EOF only after its data
    async fn run_transfer<S: Syscalls>(sys: S, up: usize, down: usize) -> (u64, u64, Counters) {
        let Rig { x, y, a, b } = rig().await;
        let up_data = pattern(up, 1);
        let down_data = pattern(down, 2);
        let counters = Counters::default();

        let (mut xr, mut xw) = x.into_split();
        let (mut yr, mut yw) = y.into_split();

        let relay = relay(&sys, &a, &b, &counters);

        let send_up = {
            let data = up_data.clone();
            async move {
                xw.write_all(&data).await.unwrap();
                xw.shutdown().await.unwrap();
            }
        };
        let send_down = {
            let data = down_data.clone();
            async move {
                yw.write_all(&data).await.unwrap();
                yw.shutdown().await.unwrap();
            }
        };
        let recv_at_y = async move {
            let mut got = Vec::new();
            yr.read_to_end(&mut got).await.unwrap();
            got
        };
        let recv_at_x = async move {
            let mut got = Vec::new();
            xr.read_to_end(&mut got).await.unwrap();
            got
        };

        let (res, (), (), got_y, got_x) =
            within(async { tokio::join!(relay, send_up, send_down, recv_at_y, recv_at_x) }).await;
        let (a_to_b, b_to_a) = res.unwrap();

        assert!(got_y == up_data, "bytes a -> b differ");
        assert!(got_x == down_data, "bytes b -> a differ");
        assert_eq!(got_y.len() as u64, a_to_b);
        assert_eq!(got_x.len() as u64, b_to_a);
        (a_to_b, b_to_a, counters)
    }

    #[tokio::test]
    async fn transfers_both_ways_and_counts() {
        let (up, down, c) = run_transfer(Kernel, 8 << 20, 5 << 20).await;
        assert_eq!((up, down), (8 << 20, 5 << 20));
        // `a` is the monitored side: it is read for the upload and written for the download.
        assert_eq!(c.read_a.load(Ordering::Relaxed), 8 << 20);
        assert_eq!(c.wrote_a.load(Ordering::Relaxed), 5 << 20);
    }

    #[tokio::test]
    async fn empty_and_tiny_transfers() {
        assert_eq!(run_transfer(Kernel, 0, 0).await.0, 0);
        let (up, down, _) = run_transfer(Kernel, 1, 0).await;
        assert_eq!((up, down), (1, 0));
        let (up, down, _) = run_transfer(Kernel, 0, 3).await;
        assert_eq!((up, down), (0, 3));
    }

    /// The `a` side sends everything and half-closes, then the `b` side answers after seeing EOF:
    /// the answer must still reach `a`, which means the relay did not tear down on the first EOF.
    #[tokio::test]
    async fn half_close_keeps_the_other_direction_open() {
        let Rig { x, y, a, b } = rig().await;
        let (mut xr, mut xw) = x.into_split();
        let (mut yr, mut yw) = y.into_split();
        let counters = Counters::default();

        let relay = relay(&Kernel, &a, &b, &counters);
        let client = async move {
            xw.write_all(b"request").await.unwrap();
            xw.shutdown().await.unwrap();
            let mut got = Vec::new();
            xr.read_to_end(&mut got).await.unwrap();
            got
        };
        let server = async move {
            let mut got = Vec::new();
            // read_to_end only returns after the relay shut y down for writing
            yr.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, b"request");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            yw.write_all(b"response after EOF").await.unwrap();
            yw.shutdown().await.unwrap();
        };
        let (res, got, ()) = within(async { tokio::join!(relay, client, server) }).await;
        assert_eq!(got, b"response after EOF");
        assert_eq!(res.unwrap(), (7, 18));
    }

    /// A reader slower than the writer: the destination's buffer fills, `splice` returns EAGAIN and
    /// the relay must wait for writability without losing or duplicating bytes.
    #[tokio::test]
    async fn slow_reader_exercises_eagain() {
        let Rig { x, y, a, b } = rig().await;
        let data = pattern(24 << 20, 7);
        let (_xr, mut xw) = x.into_split();
        let (mut yr, mut yw) = y.into_split();
        let counters = Counters::default();

        let relay_fut = relay(&Kernel, &a, &b, &counters);
        let send = {
            let data = data.clone();
            async move {
                xw.write_all(&data).await.unwrap();
                xw.shutdown().await.unwrap();
            }
        };
        let recv = async move {
            let mut got = Vec::with_capacity(24 << 20);
            let mut buf = vec![0u8; 4096];
            loop {
                let n = yr.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
                if got.len() % (1 << 20) < 4096 {
                    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                }
            }
            // the relay ends when both directions have seen EOF
            yw.shutdown().await.unwrap();
            got
        };
        let (res, (), got) = within(async { tokio::join!(relay_fut, send, recv) }).await;
        assert!(got == data);
        assert_eq!(res.unwrap().0, data.len() as u64);
    }

    #[tokio::test]
    async fn falls_back_when_splice_from_socket_is_unsupported() {
        for errno in [libc::EINVAL, libc::ENOSYS, libc::EOPNOTSUPP] {
            let sys = Faulty {
                to_pipe_errno: Some(errno),
                ..Faulty::none()
            };
            let (up, down, c) = run_transfer(sys, 3 << 20, 2 << 20).await;
            assert_eq!((up, down), (3 << 20, 2 << 20));
            assert_eq!(c.read_a.load(Ordering::Relaxed), 3 << 20);
            assert_eq!(c.wrote_a.load(Ordering::Relaxed), 2 << 20);
        }
    }

    /// The first splice into the pipe works, the first splice out of it doesn't: the bytes in the
    /// pipe have to be delivered by the fallback before it carries on.
    #[tokio::test]
    async fn falls_back_without_losing_the_bytes_in_the_pipe() {
        for errno in [libc::EINVAL, libc::ENOSYS, libc::EOPNOTSUPP] {
            let sys = Faulty {
                from_pipe_errno: Some(errno),
                ..Faulty::none()
            };
            let (up, down, c) = run_transfer(sys, 6 << 20, 4 << 20).await;
            assert_eq!((up, down), (6 << 20, 4 << 20));
            assert_eq!(c.read_a.load(Ordering::Relaxed), 6 << 20);
            assert_eq!(c.wrote_a.load(Ordering::Relaxed), 4 << 20);
        }
    }

    /// After a splice has worked, the same errno is a real error, not a reason to fall back
    #[tokio::test]
    async fn unsupported_errors_after_success_are_errors() {
        let Rig { x, y, a, b } = rig().await;
        let sys = Faulty {
            from_pipe_errno: Some(libc::EINVAL),
            from_pipe_after: 1,
            ..Faulty::none()
        };
        let (_xr, mut xw) = x.into_split();
        let (_yr, _yw) = y.into_split();

        let data = pattern(8 << 20, 3);
        let writer = tokio::spawn(async move {
            let _ = xw.write_all(&data).await;
            xw
        });
        let err = within(relay(&sys, &a, &b, &())).await.unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
        writer.abort();
    }

    /// A connected pair of MPTCP sockets, or `None` if the kernel has no MPTCP
    fn mptcp_pair() -> Option<(TcpStream, TcpStream)> {
        use socket2::{Domain, Protocol, Socket, Type};

        let listener = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::MPTCP)).ok()?;
        listener
            .bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
            .ok()?;
        listener.listen(8).ok()?;
        let addr = listener.local_addr().ok()?;
        let client = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::MPTCP)).ok()?;
        client.connect(&addr).ok()?;
        let (accepted, _) = listener.accept().ok()?;
        for s in [&client, &accepted] {
            s.set_nonblocking(true).unwrap();
        }
        Some((
            TcpStream::from_std(client.into()).unwrap(),
            TcpStream::from_std(accepted.into()).unwrap(),
        ))
    }

    /// The sockets of the OpenMPTCProuter relay: MPTCP on one side, plain TCP on the other
    #[tokio::test]
    async fn mptcp_on_either_side() {
        let Some(_) = mptcp_pair() else {
            eprintln!("no MPTCP on this kernel, skipping");
            return;
        };
        for mptcp_is_a in [true, false] {
            let (m_outer, m_inner) = mptcp_pair().unwrap();
            let (p_outer, p_inner) = tcp_pair().await;
            // outer: where the test talks, inner: what the relay is given
            let (x, a, b, y) = if mptcp_is_a {
                (m_outer, m_inner, p_inner, p_outer)
            } else {
                (p_outer, p_inner, m_inner, m_outer)
            };
            let up_data = pattern(3 << 20, 5);
            let down_data = pattern(2 << 20, 6);
            let (mut xr, mut xw) = x.into_split();
            let (mut yr, mut yw) = y.into_split();
            let counters = Counters::default();

            let send_up = async {
                xw.write_all(&up_data).await.unwrap();
                xw.shutdown().await.unwrap();
            };
            let send_down = async {
                yw.write_all(&down_data).await.unwrap();
                yw.shutdown().await.unwrap();
            };
            let recv_y = async {
                let mut got = Vec::new();
                yr.read_to_end(&mut got).await.unwrap();
                got
            };
            let recv_x = async {
                let mut got = Vec::new();
                xr.read_to_end(&mut got).await.unwrap();
                got
            };
            let (res, (), (), got_y, got_x) =
                within(async { tokio::join!(relay(&Kernel, &a, &b, &counters), send_up, send_down, recv_y, recv_x) })
                    .await;
            assert_eq!(res.unwrap(), (3 << 20, 2 << 20), "mptcp_is_a: {mptcp_is_a}");
            assert!(got_y == up_data && got_x == down_data);
        }
    }

    /// `x` sends `hello`, a byte of TCP urgent data, then `world`. The userspace copy reads with
    /// `recv(2)`, which skips the urgent byte, so `helloworld` reaches `y`. `splice(2)` stops in front
    /// of the urgent byte instead, and keeps saying EAGAIN there (or 0, once the FIN is in) until
    /// something reads past it.
    async fn urgent_data<S: Syscalls>(sys: S, fin_right_away: bool) {
        let Rig { mut x, mut y, a, b } = rig().await;

        let relay = relay(&sys, &a, &b, &());
        let test = async {
            x.write_all(b"hello").await.unwrap();
            socket2::SockRef::from(&x).send_out_of_band(b"X").unwrap();
            x.write_all(b"world").await.unwrap();
            if fin_right_away {
                x.shutdown().await.unwrap();
            }
            let mut got = [0u8; 10];
            tokio::time::timeout(std::time::Duration::from_secs(5), y.read_exact(&mut got))
                .await
                .expect("the relay stalled at the urgent data")
                .expect("the relay cut the stream at the urgent data");
            assert_eq!(&got, b"helloworld");
            if !fin_right_away {
                x.shutdown().await.unwrap();
            }
            let mut rest = Vec::new();
            y.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty());
            y.shutdown().await.unwrap();
        };
        let (res, ()) = within(async { tokio::join!(relay, test) }).await;
        assert_eq!(res.unwrap(), (10, 0));
    }

    #[tokio::test]
    async fn urgent_data_does_not_stall_the_relay() {
        urgent_data(Kernel, false).await;
        // the userspace copy, for reference
        urgent_data(
            Faulty {
                to_pipe_errno: Some(libc::EINVAL),
                ..Faulty::none()
            },
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn urgent_data_does_not_end_the_stream() {
        urgent_data(Kernel, true).await;
        urgent_data(
            Faulty {
                to_pipe_errno: Some(libc::EINVAL),
                ..Faulty::none()
            },
            true,
        )
        .await;
    }

    /// `y` sends everything, half-closes, then resets the connection: when `x` half-closes later, `b`
    /// is gone and its shutdown fails with ENOTCONN. tokio's `copy_bidirectional` takes that as done,
    /// and so does the relay.
    #[tokio::test]
    async fn eof_after_the_other_side_reset() {
        let Rig { mut x, mut y, a, b } = rig().await;

        let relay = relay(&Kernel, &a, &b, &());
        let test = async {
            y.write_all(b"response").await.unwrap();
            y.shutdown().await.unwrap();
            let mut got = Vec::new();
            x.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, b"response");

            socket2::SockRef::from(&y)
                .set_linger(Some(std::time::Duration::ZERO))
                .unwrap();
            drop(y);
            // `b` has no peer once the RST is in
            while b.peer_addr().is_ok() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            x.shutdown().await.unwrap();
        };
        let (res, ()) = within(async { tokio::join!(relay, test) }).await;
        assert_eq!(res.unwrap(), (0, 8));
    }

    /// Refuses to splice from the socket, and remembers the pipe it was given
    #[derive(Default)]
    struct Refusing {
        pipe: std::sync::Mutex<Option<(RawFd, libc::ino_t)>>,
    }

    fn inode(fd: RawFd) -> Option<libc::ino_t> {
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `st` has room for a `stat`, which `fstat` fills when it succeeds.
        unsafe { (libc::fstat(fd, st.as_mut_ptr()) == 0).then(|| st.assume_init().st_ino) }
    }

    impl Syscalls for Refusing {
        fn splice_to_pipe(&self, _: RawFd, pipe: RawFd, _: usize) -> io::Result<usize> {
            *self.pipe.lock().unwrap() = inode(pipe).map(|ino| (pipe, ino));
            Err(io::Error::from_raw_os_error(libc::EINVAL))
        }

        fn splice_from_pipe(&self, _: RawFd, _: RawFd, _: usize) -> io::Result<usize> {
            unreachable!("nothing was spliced into the pipe")
        }

        fn sigpipe_is_harmless(&self) -> bool {
            true
        }
    }

    /// Says EAGAIN to every other splice from a socket that has data, as when the data comes in
    /// right after the call, and counts the bytes spliced out of the pipe
    #[derive(Default)]
    struct Late {
        to_pipe_calls: AtomicUsize,
        spliced_out: AtomicU64,
    }

    impl Syscalls for Late {
        fn splice_to_pipe(&self, socket: RawFd, pipe: RawFd, len: usize) -> io::Result<usize> {
            if self.to_pipe_calls.fetch_add(1, Ordering::Relaxed) % 2 == 0 && recv_has_data(socket)? {
                return Err(io::Error::from_raw_os_error(libc::EAGAIN));
            }
            Kernel.splice_to_pipe(socket, pipe, len)
        }

        fn splice_from_pipe(&self, pipe: RawFd, socket: RawFd, len: usize) -> io::Result<usize> {
            let n = Kernel.splice_from_pipe(pipe, socket, len)?;
            self.spliced_out.fetch_add(n as u64, Ordering::Relaxed);
            Ok(n)
        }

        fn sigpipe_is_harmless(&self) -> bool {
            true
        }
    }

    /// Bytes that come in between an EAGAIN and the check for urgent data are not urgent data: they
    /// are spliced, not read through userspace.
    #[tokio::test]
    async fn data_that_comes_in_after_eagain_is_spliced() {
        let Rig { mut x, mut y, a, b } = rig().await;
        let sys = Late::default();
        let data = pattern(4 << 20, 4);

        let relay = relay(&sys, &a, &b, &());
        let test = async {
            let send = async {
                for chunk in data.chunks(64 << 10) {
                    x.write_all(chunk).await.unwrap();
                    tokio::task::yield_now().await;
                }
                x.shutdown().await.unwrap();
            };
            let recv = async {
                let mut got = Vec::new();
                y.read_to_end(&mut got).await.unwrap();
                got
            };
            let ((), got) = tokio::join!(send, recv);
            assert!(got == data);
            y.shutdown().await.unwrap();
        };
        let (res, ()) = within(async { tokio::join!(relay, test) }).await;
        assert_eq!(res.unwrap(), (4 << 20, 0));
        assert_eq!(
            sys.spliced_out.load(Ordering::Relaxed),
            4 << 20,
            "bytes went through userspace"
        );
    }

    /// A process in which `SIGPIPE` has its default action, which ends it
    struct DefaultSigpipe;

    impl Syscalls for DefaultSigpipe {
        fn splice_to_pipe(&self, _: RawFd, _: RawFd, _: usize) -> io::Result<usize> {
            unreachable!("splice(2) while SIGPIPE would end the process")
        }

        fn splice_from_pipe(&self, _: RawFd, _: RawFd, _: usize) -> io::Result<usize> {
            unreachable!("splice(2) while SIGPIPE would end the process")
        }

        fn sigpipe_is_harmless(&self) -> bool {
            false
        }
    }

    /// A peer that goes away during a splice would end the process: the relay copies through
    /// userspace instead, where `send` doesn't raise `SIGPIPE`.
    #[tokio::test]
    async fn copies_when_sigpipe_would_end_the_process() {
        let (up, down, c) = run_transfer(DefaultSigpipe, 3 << 20, 2 << 20).await;
        assert_eq!((up, down), (3 << 20, 2 << 20));
        assert_eq!(c.read_a.load(Ordering::Relaxed), 3 << 20);
        assert_eq!(c.wrote_a.load(Ordering::Relaxed), 2 << 20);
    }

    /// The test harness, like any Rust executable, ignores `SIGPIPE`: the relay does splice there.
    #[test]
    fn sigpipe_is_ignored_by_the_rust_runtime() {
        assert!(sigpipe_is_harmless());
    }

    /// With the default action, in a child process so that the other tests keep ignoring `SIGPIPE`
    #[test]
    fn sigpipe_default_action_is_seen() {
        // SAFETY: the child only makes async-signal-safe calls (`signal`, `sigaction`, `_exit`).
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0, "fork: {}", io::Error::last_os_error());
            if pid == 0 {
                libc::signal(libc::SIGPIPE, libc::SIG_DFL);
                libc::_exit(if sigpipe_is_harmless() { 1 } else { 0 });
            }
            let mut status = 0;
            assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
            assert!(
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                "status {status:#x}"
            );
        }
    }

    /// The userspace copy that takes over doesn't use the pipe: it must not keep it open (two
    /// descriptors, and a share of the user's pipe pages) for the rest of the connection.
    #[tokio::test]
    async fn fallback_releases_the_pipe() {
        let Rig { mut x, mut y, a, b } = rig().await;
        let sys = Refusing::default();

        let relay = relay(&sys, &a, &b, &());
        let test = async {
            x.write_all(b"ping").await.unwrap();
            let mut got = [0u8; 4];
            y.read_exact(&mut got).await.unwrap();
            // the copy is running now
            let recorded = *sys.pipe.lock().unwrap();
            let (fd, ino) = recorded.expect("the relay never tried to splice");
            assert_ne!(inode(fd), Some(ino), "the pipe is still open");
            x.shutdown().await.unwrap();
            y.shutdown().await.unwrap();
        };
        let (res, ()) = within(async { tokio::join!(relay, test) }).await;
        assert_eq!(res.unwrap(), (4, 0));
    }

    #[tokio::test]
    async fn peer_reset_is_an_error() {
        let Rig { x, y, a, b } = rig().await;
        let (mut xr, mut xw) = x.into_split();
        drop(y);

        let relay_fut = relay(&Kernel, &a, &b, &());
        let drive = async move {
            // After y is gone, writing to b ends in EPIPE/ECONNRESET sooner or later.
            let chunk = pattern(1 << 16, 9);
            for _ in 0..64 {
                if xw.write_all(&chunk).await.is_err() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            let mut sink = Vec::new();
            let _ = xr.read_to_end(&mut sink).await;
        };
        let res = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            tokio::select! {
                res = relay_fut => res,
                () = drive => unreachable!("relay should have failed first"),
            }
        })
        .await
        .expect("relay hung");
        assert!(res.is_err());
    }
}
