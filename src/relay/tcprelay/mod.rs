//! Relay for TCP implementation

// Allow for futures
// Maybe removed in the future
#![allow(clippy::unnecessary_mut_passed)]

use std::{io, marker::Unpin};

use futures::{future::FusedFuture, select, Future};
use tokio::{
    self,
    io::{AsyncRead, AsyncReadExt},
    net::TcpStream,
};

mod aead;
pub mod client;
mod connection;
mod crypto_io;
mod http_local;
pub mod local;
mod monitor;
mod redir_local;
pub mod server;
mod socks5_local;
mod stream;
mod sys;
mod tunnel_local;
mod utils;

pub use self::{
    connection::{Connection, TcpConnection},
    crypto_io::CryptoStream,
};

pub(crate) use self::local::{connect_proxy_server, proxy_server_handshake};

const BUFFER_SIZE: usize = 8 * 1024; // 8K buffer

/// Secured TcpStream
pub type STcpStream = Connection<TcpStream>;

/// Establish tunnel between server and client
// pub fn tunnel<CF, CFI, SF, SFI>(addr: Address, c2s: CF, s2c: SF) -> impl Future<Item = (), Error = io::Error> + Send
pub async fn tunnel<CF, CFI, SF, SFI>(mut c2s: CF, mut s2c: SF) -> io::Result<()>
where
    CF: Future<Output = io::Result<CFI>> + Unpin + FusedFuture,
    SF: Future<Output = io::Result<SFI>> + Unpin + FusedFuture,
{
    select! {
        r1 = c2s => r1.map(|_| ()),
        r2 = s2c => r2.map(|_| ()),
    }
}

/// Hold the connection until EOF
pub async fn ignore_until_end<R>(r: &mut R) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
{
    let mut buf = [0u8; BUFFER_SIZE];
    let mut amt = 0u64;
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        amt += n as u64;
    }
    Ok(amt)
}
