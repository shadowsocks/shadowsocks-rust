//! Shadowsocks Local Utilities

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::future::Future;
use std::{io, net::SocketAddr, time::Duration};

use log::{debug, trace};
#[cfg(any(target_os = "linux", target_os = "android"))]
use shadowsocks::relay::tcprelay::splice::{copy_bidirectional_splice, copy_bidirectional_splice_monitored};
use shadowsocks::{
    config::ServerConfig,
    relay::{socks5::Address, tcprelay::utils::copy_encrypted_bidirectional},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional},
    time,
};

use crate::local::net::{AutoProxyIo, SpliceIo};

pub(crate) async fn establish_tcp_tunnel<P, S>(
    svr_cfg: &ServerConfig,
    plain: &mut P,
    shadow: &mut S,
    peer_addr: SocketAddr,
    target_addr: &Address,
) -> io::Result<()>
where
    P: AsyncRead + AsyncWrite + SpliceIo + Unpin,
    S: AsyncRead + AsyncWrite + AutoProxyIo + SpliceIo + Unpin,
{
    if shadow.is_proxied() {
        debug!(
            "established tcp tunnel {} <-> {} through server {} (outbound: {})",
            peer_addr,
            target_addr,
            svr_cfg.tcp_external_addr(),
            svr_cfg.addr(),
        );
    } else {
        return establish_tcp_tunnel_bypassed(plain, shadow, peer_addr, target_addr).await;
    }

    // https://github.com/shadowsocks/shadowsocks-rust/issues/232
    //
    // Protocols like FTP, clients will wait for servers to send Welcome Message without sending anything.
    //
    // Wait at most 500ms, and then sends handshake packet to remote servers.
    {
        let mut buffer = [0u8; 8192];
        match time::timeout(Duration::from_millis(500), plain.read(&mut buffer)).await {
            Ok(Ok(0)) => {
                // EOF. Just terminate right here.
                return Ok(());
            }
            Ok(Ok(n)) => {
                // Send the first packet.
                shadow.write_all(&buffer[..n]).await?;
            }
            Ok(Err(err)) => return Err(err),
            Err(..) => {
                // Timeout. Send handshake to server.
                let _ = shadow.write(&[]).await?;

                trace!(
                    "tcp tunnel {} -> {} (proxied) sent handshake without data",
                    peer_addr, target_addr
                );
            }
        }
    }

    let result = if let Some(splice) = splice_tunnel(shadow, plain) {
        splice.await
    } else {
        copy_encrypted_bidirectional(svr_cfg.method(), shadow, plain).await
    };

    match result {
        Ok((wn, rn)) => {
            trace!(
                "tcp tunnel {} <-> {} (proxied) closed, L2R {} bytes, R2L {} bytes",
                peer_addr, target_addr, rn, wn
            );
        }
        Err(err) => {
            trace!(
                "tcp tunnel {} <-> {} (proxied) closed with error: {}",
                peer_addr, target_addr, err
            );
        }
    }

    Ok(())
}

/// Relays between the server socket and the client socket in the kernel, if both are plain TCP
/// sockets, and the cipher leaves the bytes alone
///
/// Returns `None`, without having touched the streams, if that isn't possible: the caller copies
/// through userspace then. The result is the number of bytes from the server and from the client.
///
/// The streams are inspected here, outside of the returned future, which only holds the sockets.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn splice_tunnel<'a, P, S>(shadow: &'a S, plain: &'a P) -> Option<impl Future<Output = io::Result<(u64, u64)>> + 'a>
where
    P: SpliceIo,
    S: SpliceIo,
{
    let (shadow_socket, plain_socket, flow_stat) = (
        shadow.splice_socket()?,
        plain.splice_socket()?,
        shadow.splice_flow_stat()?,
    );

    Some(copy_bidirectional_splice_monitored(
        shadow_socket,
        plain_socket,
        flow_stat,
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn splice_tunnel<P, S>(_shadow: &S, _plain: &P) -> Option<std::future::Ready<io::Result<(u64, u64)>>>
where
    P: SpliceIo,
    S: SpliceIo,
{
    None
}

/// Relays between the client socket and the target socket in the kernel, if both are plain TCP
/// sockets. `None`, without having touched the streams, if not.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn splice_bypassed_tunnel<'a, P, S>(
    plain: &'a P,
    shadow: &'a S,
) -> Option<impl Future<Output = io::Result<(u64, u64)>> + 'a>
where
    P: SpliceIo,
    S: SpliceIo,
{
    Some(copy_bidirectional_splice(
        plain.splice_socket()?,
        shadow.splice_socket()?,
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn splice_bypassed_tunnel<P, S>(_plain: &P, _shadow: &S) -> Option<std::future::Ready<io::Result<(u64, u64)>>>
where
    P: SpliceIo,
    S: SpliceIo,
{
    None
}

pub(crate) async fn establish_tcp_tunnel_bypassed<P, S>(
    plain: &mut P,
    shadow: &mut S,
    peer_addr: SocketAddr,
    target_addr: &Address,
) -> io::Result<()>
where
    P: AsyncRead + AsyncWrite + SpliceIo + Unpin,
    S: AsyncRead + AsyncWrite + SpliceIo + Unpin,
{
    debug!("established tcp tunnel {} <-> {} bypassed", peer_addr, target_addr);

    let result = if let Some(splice) = splice_bypassed_tunnel(plain, shadow) {
        splice.await
    } else {
        copy_bidirectional(plain, shadow).await
    };

    match result {
        Ok((rn, wn)) => {
            trace!(
                "tcp tunnel {} <-> {} (bypassed) closed, L2R {} bytes, R2L {} bytes",
                peer_addr, target_addr, rn, wn
            );
        }
        Err(err) => {
            trace!(
                "tcp tunnel {} <-> {} (bypassed) closed with error: {}",
                peer_addr, target_addr, err
            );
        }
    }

    Ok(())
}
