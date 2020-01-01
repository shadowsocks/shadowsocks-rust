//! Split halfs for TcpStream

use std::{
    io,
    marker::{PhantomData, Unpin},
    mem::MaybeUninit,
    pin::Pin,
    task,
};

use bytes::{Buf, BufMut};
use tokio::io::{AsyncRead, AsyncWrite};

use super::TcpStream;

pub struct ReadHalf<'a> {
    stream: *mut TcpStream,
    phantom: PhantomData<&'a TcpStream>,
}

impl<'a> ReadHalf<'a> {
    fn stream(&self) -> &'a mut TcpStream {
        unsafe { &mut *self.stream }
    }
}

impl AsRef<TcpStream> for ReadHalf<'_> {
    fn as_ref(&self) -> &TcpStream {
        unsafe { &*self.stream }
    }
}

impl AsyncRead for ReadHalf<'_> {
    unsafe fn prepare_uninitialized_buffer(&self, buf: &mut [MaybeUninit<u8>]) -> bool {
        self.stream().prepare_uninitialized_buffer(buf)
    }

    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut [u8]) -> task::Poll<io::Result<usize>> {
        Pin::new(self.stream()).poll_read(cx, buf)
    }

    fn poll_read_buf<B: BufMut>(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut B,
    ) -> task::Poll<io::Result<usize>> {
        Pin::new(self.stream()).poll_read_buf(cx, buf)
    }
}

unsafe impl<'a> Send for ReadHalf<'a> {}
unsafe impl<'a> Sync for ReadHalf<'a> {}
impl<'a> Unpin for ReadHalf<'a> {}

// impl<'a> !RefUnwindSafe for ReadHalf<'a> {}
// impl<'a> !UnwindSafe for ReadHalf<'a> {}

pub struct WriteHalf<'a> {
    stream: *mut TcpStream,
    phantom: PhantomData<&'a TcpStream>,
}

impl<'a> WriteHalf<'a> {
    fn stream(&self) -> &'a mut TcpStream {
        unsafe { &mut *self.stream }
    }
}

impl AsRef<TcpStream> for WriteHalf<'_> {
    fn as_ref(&self) -> &TcpStream {
        unsafe { &*self.stream }
    }
}

impl AsyncWrite for WriteHalf<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> task::Poll<Result<usize, io::Error>> {
        Pin::new(self.stream()).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Result<(), io::Error>> {
        Pin::new(self.stream()).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Result<(), io::Error>> {
        Pin::new(self.stream()).poll_shutdown(cx)
    }

    fn poll_write_buf<B: Buf>(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut B,
    ) -> task::Poll<Result<usize, io::Error>> {
        Pin::new(self.stream()).poll_write_buf(cx, buf)
    }
}

unsafe impl<'a> Send for WriteHalf<'a> {}
unsafe impl<'a> Sync for WriteHalf<'a> {}
impl<'a> Unpin for WriteHalf<'a> {}

// impl<'a> !RefUnwindSafe for WriteHalf<'a> {}
// impl<'a> !UnwindSafe for WriteHalf<'a> {}

pub fn split(stream: &mut TcpStream) -> (ReadHalf, WriteHalf) {
    let rhalf = ReadHalf {
        stream: stream,
        phantom: PhantomData,
    };

    let whalf = WriteHalf {
        stream: stream,
        phantom: PhantomData,
    };

    (rhalf, whalf)
}
