use std::io;

use futures::{try_ready, Async, Future, Poll};
use tokio_io::{
    io::{write_all, WriteAll},
    AsyncWrite,
};

/// Write all bytes without returning the internal bytes buffer
pub struct WriteBytes<W, B>
where
    W: AsyncWrite,
    B: AsRef<[u8]>,
{
    inner: WriteAll<W, B>,
}

impl<W, B> WriteBytes<W, B>
where
    W: AsyncWrite,
    B: AsRef<[u8]>,
{
    fn new(writer: W, bytes: B) -> WriteBytes<W, B> {
        WriteBytes {
            inner: write_all(writer, bytes),
        }
    }
}

impl<W, B> Future for WriteBytes<W, B>
where
    W: AsyncWrite,
    B: AsRef<[u8]>,
{
    type Error = io::Error;
    type Item = W;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let (w, _) = try_ready!(self.inner.poll());
        Ok(Async::Ready(w))
    }
}

/// Write all bytes without returning the internal bytes buffer
pub fn write_bytes<W: AsyncWrite, B: AsRef<[u8]>>(w: W, b: B) -> WriteBytes<W, B> {
    WriteBytes::new(w, b)
}
