//! Server traffic monitor

use std::{
    io::{self, Read, Write},
    ops::{Deref, DerefMut},
};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    prelude::Async,
};

use super::context::SharedTcpServerContext;

pub struct TcpMonStream {
    stream: TcpStream,
    context: SharedTcpServerContext,
}

impl TcpMonStream {
    pub fn new(c: SharedTcpServerContext, s: TcpStream) -> TcpMonStream {
        TcpMonStream { stream: s, context: c }
    }
}

impl Read for TcpMonStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.stream.read(buf)?;
        self.context.incr_rx(n);
        Ok(n)
    }
}

impl Write for TcpMonStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.stream.write(buf)?;
        self.context.incr_tx(n);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl AsyncRead for TcpMonStream {}

impl AsyncWrite for TcpMonStream {
    fn shutdown(&mut self) -> Result<Async<()>, io::Error> {
        AsyncWrite::shutdown(&mut self.stream)
    }
}

impl Deref for TcpMonStream {
    type Target = TcpStream;

    fn deref(&self) -> &TcpStream {
        &self.stream
    }
}

impl DerefMut for TcpMonStream {
    fn deref_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }
}
