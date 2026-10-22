//! Streams whose bytes can be relayed by the kernel

use tokio::net::TcpStream;

use crate::net::FlowStat;

/// A stream that may be a kernel TCP socket behind a thin wrapper
///
/// Relaying between two such streams doesn't need to read the bytes into the process: see
/// `shadowsocks::relay::tcprelay::splice`. Both methods default to "no", which is always correct.
pub trait SpliceIo {
    /// The socket behind this stream, if everything read from and written to the stream is exactly
    /// what is read from and written to the socket, and no byte of the stream is held in userspace
    fn splice_socket(&self) -> Option<&TcpStream> {
        None
    }

    /// The flow statistics that the stream would update, if `splice_socket` is `Some`
    fn splice_flow_stat(&self) -> Option<&FlowStat> {
        None
    }
}

impl SpliceIo for TcpStream {
    fn splice_socket(&self) -> Option<&TcpStream> {
        Some(self)
    }
}
