//! Shadowsocks Local Utilities

use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use log::{debug, trace};
use shadowsocks::{
    config::ServerConfig,
    relay::{socks5::Address, tcprelay::utils::copy_encrypted_bidirectional},
};
use tokio::{
    io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time,
};

use crate::local::net::AutoProxyIo;

pub(crate) async fn establish_tcp_tunnel<P, S>(
    svr_cfg: &ServerConfig,
    plain: &mut P,
    shadow: &mut S,
    peer_addr: SocketAddr,
    target_addr: &Address,
) -> io::Result<()>
where
    P: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + AutoProxyIo + Unpin,
{
    if shadow.is_proxied() {
        debug!(
            "established tcp tunnel {} <-> {} through sever {} (outbound: {})",
            peer_addr,
            target_addr,
            svr_cfg.external_addr(),
            svr_cfg.addr(),
        );
    } else {
        debug!("established tcp tunnel {} <-> {} bypassed", peer_addr, target_addr);
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
                shadow.write(&[]).await?;

                trace!(
                    "tcp tunnel {} -> {} (proxied) sent handshake without data",
                    peer_addr,
                    target_addr
                );
            }
        }
    }

    match copy_encrypted_bidirectional(svr_cfg.method(), shadow, plain).await {
        Ok((wn, rn)) => {
            trace!(
                "tcp tunnel {} <-> {} (proxied) closed, L2R {} bytes, R2L {} bytes",
                peer_addr,
                target_addr,
                rn,
                wn
            );
        }
        Err(err) => {
            trace!(
                "tcp tunnel {} <-> {} (proxied) closed with error: {}",
                peer_addr,
                target_addr,
                err
            );
        }
    }

    Ok(())
}

async fn establish_tcp_tunnel_bypassed<P, S>(
    plain: &mut P,
    shadow: &mut S,
    peer_addr: SocketAddr,
    target_addr: &Address,
) -> io::Result<()>
where
    P: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    match copy_bidirectional(plain, shadow).await {
        Ok((rn, wn)) => {
            trace!(
                "tcp tunnel {} <-> {} (bypassed) closed, L2R {} bytes, R2L {} bytes",
                peer_addr,
                target_addr,
                rn,
                wn
            );
        }
        Err(err) => {
            trace!(
                "tcp tunnel {} <-> {} (bypassed) closed with error: {}",
                peer_addr,
                target_addr,
                err
            );
        }
    }

    Ok(())
}

/// Helper function for converting IPv4 mapped IPv6 address
///
/// This is the same as `Ipv6Addr::to_ipv4_mapped`, but it is still unstable in the current libstd
#[allow(unused)]
pub(crate) fn to_ipv4_mapped(ipv6: &Ipv6Addr) -> Option<Ipv4Addr> {
    match ipv6.octets() {
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d] => Some(Ipv4Addr::new(a, b, c, d)),
        _ => None,
    }
}
