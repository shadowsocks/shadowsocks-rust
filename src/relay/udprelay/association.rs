//! UDP Association
//!
//! Working like a NAT proxy

#![allow(dead_code)]

use std::{
    io::{self, Cursor, Read},
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use async_trait::async_trait;
use bytes::BytesMut;
use futures::future;
use log::{debug, error, warn};
use tokio::{
    self,
    net::udp::{RecvHalf, SendHalf},
    sync::{mpsc, oneshot},
};

use crate::{
    config::{ServerAddr, ServerConfig},
    context::Context,
    relay::{
        loadbalancing::server::{ServerData, SharedServerStatistic},
        socks5::Address,
        sys::create_udp_socket_with_context,
    },
};

use super::{
    crypto_io::{decrypt_payload, encrypt_payload},
    MAXIMUM_UDP_PAYLOAD_SIZE,
};

#[async_trait]
pub trait ProxySend {
    async fn send_packet(&mut self, data: Vec<u8>) -> io::Result<()>;
}

pub struct ProxyAssociation {
    tx: mpsc::Sender<(Address, Vec<u8>)>,
    watchers: Vec<oneshot::Sender<()>>,
}

impl ProxyAssociation {
    pub async fn associate_proxied<S, H>(
        src_addr: SocketAddr,
        server: SharedServerStatistic<S>,
        sender: H,
    ) -> io::Result<ProxyAssociation>
    where
        S: ServerData + Send + 'static,
        H: ProxySend + Send + 'static,
    {
        // Create a socket for receiving packets
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);

        let remote_udp = create_udp_socket_with_context(&local_addr, server.context()).await?;
        let remote_bind_addr = remote_udp.local_addr().expect("determine port bound to");

        debug!("created UDP association {} <-> {}", src_addr, remote_bind_addr);

        // Create a channel for sending packets to remote
        // FIXME: Channel size 1024?
        let (tx, rx) = mpsc::channel::<(Address, Vec<u8>)>(1024);

        // Splits socket into sender and receiver
        let (remote_receiver, remote_sender) = remote_udp.split();

        // LOCAL -> REMOTE task
        // All packets will be sent directly to proxy
        tokio::spawn(Self::l2r_packet_proxied(src_addr, server.clone(), rx, remote_sender));

        // REMOTE <- LOCAL task
        let (remote_watcher_tx, remote_watcher_rx) = oneshot::channel::<()>();
        tokio::spawn(Self::r2l_packet(
            src_addr,
            server,
            sender,
            remote_receiver,
            remote_watcher_rx,
        ));

        let watchers = vec![remote_watcher_tx];

        Ok(ProxyAssociation { tx, watchers })
    }

    pub async fn associate_bypassed<S, H>(
        src_addr: SocketAddr,
        server: SharedServerStatistic<S>,
        sender: H,
    ) -> io::Result<ProxyAssociation>
    where
        S: ServerData + Send + 'static,
        H: ProxySend + Send + 'static,
    {
        // Create a socket for receiving packets
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);

        let remote_udp = create_udp_socket_with_context(&local_addr, server.context()).await?;
        let remote_bind_addr = remote_udp.local_addr().expect("determine port bound to");

        debug!("created UDP association {} <-> {}", src_addr, remote_bind_addr);

        // Create a channel for sending packets to remote
        // FIXME: Channel size 1024?
        let (tx, rx) = mpsc::channel::<(Address, Vec<u8>)>(1024);

        // Splits socket into sender and receiver
        let (remote_receiver, remote_sender) = remote_udp.split();

        // LOCAL -> REMOTE task
        // All packets will be sent directly to proxy
        tokio::spawn(Self::l2r_packet_bypassed(src_addr, server.clone(), rx, remote_sender));

        // REMOTE <- LOCAL task
        let (remote_watcher_tx, remote_watcher_rx) = oneshot::channel::<()>();
        tokio::spawn(Self::r2l_packet(
            src_addr,
            server,
            sender,
            remote_receiver,
            remote_watcher_rx,
        ));

        let watchers = vec![remote_watcher_tx];

        Ok(ProxyAssociation { tx, watchers })
    }

    pub async fn associate_with_acl<S, H>(
        src_addr: SocketAddr,
        server: SharedServerStatistic<S>,
        sender: H,
    ) -> io::Result<ProxyAssociation>
    where
        S: ServerData + Send + 'static,
        H: ProxySend + Clone + Send + 'static,
    {
        // Create a socket for receiving packets
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);

        let remote_udp = create_udp_socket_with_context(&local_addr, server.context()).await?;
        let remote_bind_addr = remote_udp.local_addr().expect("determine port bound to");

        // A socket for bypassed
        let bypass_udp = create_udp_socket_with_context(&local_addr, server.context()).await?;
        let bypass_bind_addr = bypass_udp.local_addr().expect("determine port bound to");

        debug!(
            "created UDP association {} <-> {}, {}",
            src_addr, remote_bind_addr, bypass_bind_addr
        );

        // Create a channel for sending packets to remote
        // FIXME: Channel size 1024?
        let (tx, rx) = mpsc::channel::<(Address, Vec<u8>)>(1024);

        // Splits socket into sender and receiver
        let (remote_receiver, remote_sender) = remote_udp.split();
        let (bypass_receiver, bypass_sender) = bypass_udp.split();

        // LOCAL -> REMOTE task
        // Packets may be sent via proxy decided by acl rules

        tokio::spawn(Self::l2r_packet_acl(
            src_addr,
            server.clone(),
            rx,
            bypass_sender,
            remote_sender,
        ));

        let (bypass_watcher_tx, bypass_watcher_rx) = oneshot::channel::<()>();
        tokio::spawn(Self::r2l_packet(
            src_addr,
            server.clone(),
            sender.clone(),
            bypass_receiver,
            bypass_watcher_rx,
        ));

        // REMOTE <- LOCAL task
        let (remote_watcher_tx, remote_watcher_rx) = oneshot::channel::<()>();
        tokio::spawn(Self::r2l_packet(
            src_addr,
            server,
            sender,
            remote_receiver,
            remote_watcher_rx,
        ));

        let watchers = vec![bypass_watcher_tx, remote_watcher_tx];

        Ok(ProxyAssociation { tx, watchers })
    }

    pub async fn send(&mut self, target: Address, payload: Vec<u8>) {
        if let Err(..) = self.tx.send((target, payload)).await {
            // SHOULDn't HAPPEN
            unreachable!("UDP association local -> remote queue closed unexpectly");
        }
    }

    async fn l2r_packet_acl<S>(
        src_addr: SocketAddr,
        server: SharedServerStatistic<S>,
        mut rx: mpsc::Receiver<(Address, Vec<u8>)>,
        mut bypass_sender: SendHalf,
        mut remote_sender: SendHalf,
    ) where
        S: ServerData + Send + 'static,
    {
        let context = server.context();
        let svr_cfg = server.server_config();

        while let Some((addr, payload)) = rx.recv().await {
            // Check if addr should be bypassed
            let is_bypassed = context.check_target_bypassed(&addr).await;

            let res = if is_bypassed {
                Self::send_packet_bypassed(src_addr, context, &addr, &payload, &mut bypass_sender).await
            } else {
                Self::send_packet_proxied(src_addr, context, svr_cfg, &addr, &payload, &mut remote_sender).await
            };

            if let Err(err) = res {
                error!(
                    "failed to send packet {} -> {}, bypassed? {}, error: {}",
                    src_addr, addr, is_bypassed, err
                );
            }
        }

        debug!("UDP association {} -> .. task is closing", src_addr);
    }

    async fn l2r_packet_proxied<S>(
        src_addr: SocketAddr,
        server: SharedServerStatistic<S>,
        mut rx: mpsc::Receiver<(Address, Vec<u8>)>,
        mut remote_sender: SendHalf,
    ) where
        S: ServerData + Send + 'static,
    {
        let context = server.context();
        let svr_cfg = server.server_config();

        while let Some((addr, payload)) = rx.recv().await {
            let res = Self::send_packet_proxied(src_addr, context, svr_cfg, &addr, &payload, &mut remote_sender).await;

            if let Err(err) = res {
                error!("UDP association send packet {} -> {}, error: {}", src_addr, addr, err);
            }
        }

        debug!("UDP association {} -> .. task is closing", src_addr);
    }

    async fn l2r_packet_bypassed<S>(
        src_addr: SocketAddr,
        server: SharedServerStatistic<S>,
        mut rx: mpsc::Receiver<(Address, Vec<u8>)>,
        mut remote_sender: SendHalf,
    ) where
        S: ServerData + Send + 'static,
    {
        let context = server.context();

        while let Some((addr, payload)) = rx.recv().await {
            let res = Self::send_packet_bypassed(src_addr, context, &addr, &payload, &mut remote_sender).await;

            if let Err(err) = res {
                error!("UDP association send packet {} -> {}, error: {}", src_addr, addr, err);
            }
        }

        debug!("UDP association {} -> .. task is closing", src_addr);
    }

    async fn send_packet_proxied(
        src_addr: SocketAddr,
        context: &Context,
        svr_cfg: &ServerConfig,
        target: &Address,
        payload: &[u8],
        socket: &mut SendHalf,
    ) -> io::Result<()> {
        // CLIENT -> SERVER protocol: ADDRESS + PAYLOAD
        let mut send_buf = Vec::new();
        target.write_to_buf(&mut send_buf);
        send_buf.extend_from_slice(payload);

        let mut encrypt_buf = BytesMut::new();
        encrypt_payload(context, svr_cfg.method(), svr_cfg.key(), &send_buf, &mut encrypt_buf)?;

        let send_len = match svr_cfg.addr() {
            ServerAddr::SocketAddr(ref remote_addr) => socket.send_to(&encrypt_buf[..], remote_addr).await?,
            ServerAddr::DomainName(ref dname, port) => {
                lookup_then!(context, dname, *port, |addr| {
                    socket.send_to(&encrypt_buf[..], &addr).await
                })?
                .1
            }
        };

        if encrypt_buf.len() != send_len {
            warn!(
                "UDP association {} -> {} via proxy {} payload truncated, expected {} bytes, but sent {} bytes",
                src_addr,
                target,
                svr_cfg.addr(),
                encrypt_buf.len(),
                send_len
            );
        }

        #[cfg(feature = "local-flow-stat")]
        {
            context.local_flow_statistic().udp().incr_tx(send_len as u64);
        }

        Ok(())
    }

    async fn send_packet_bypassed(
        src_addr: SocketAddr,
        context: &Context,
        target: &Address,
        payload: &[u8],
        socket: &mut SendHalf,
    ) -> io::Result<()> {
        // BYPASSED, so just send it directly without any modifications

        let send_len = match *target {
            Address::SocketAddress(ref saddr) => socket.send_to(payload, saddr).await?,
            Address::DomainNameAddress(ref host, port) => {
                lookup_then!(context, host, port, |saddr| { socket.send_to(payload, &saddr).await })?.1
            }
        };

        if payload.len() != send_len {
            warn!(
                "UDP association {} -> {} payload truncated, expected {} bytes, but sent {} bytes",
                src_addr,
                target,
                payload.len(),
                send_len
            );
        }

        Ok(())
    }

    async fn r2l_packet<S, H>(
        src_addr: SocketAddr,
        server: SharedServerStatistic<S>,
        mut sender: H,
        mut socket: RecvHalf,
        watcher_rx: oneshot::Receiver<()>,
    ) -> io::Result<()>
    where
        S: ServerData + Send + 'static,
        H: ProxySend + Send + 'static,
    {
        let recv_fut = async move {
            let context = server.context();
            let svr_cfg = server.server_config();

            loop {
                match Self::recv_packet_proxied(context, svr_cfg, &mut socket).await {
                    Ok(data) => {
                        if let Err(err) = sender.send_packet(data).await {
                            error!("UDP association send {} <- .., error: {}", src_addr, err);
                        }
                    }
                    Err(err) => {
                        error!("UDP association recv {} <- .., error: {}", src_addr, err);
                    }
                }
            }
        };

        tokio::pin!(recv_fut);

        // Resolve if watcher_rx resolves
        let _ = future::select(recv_fut, watcher_rx).await;

        debug!("UDP association {} <- .. task is closing", src_addr);

        Ok(())
    }

    async fn recv_packet_proxied(
        context: &Context,
        svr_cfg: &ServerConfig,
        socket: &mut RecvHalf,
    ) -> io::Result<Vec<u8>> {
        // Waiting for response from server SERVER -> CLIENT
        // Packet length is limited by MAXIMUM_UDP_PAYLOAD_SIZE, excess bytes will be discarded.
        let mut recv_buf = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];

        let (recv_n, _) = socket.recv_from(&mut recv_buf).await?;

        let decrypt_buf = match decrypt_payload(context, svr_cfg.method(), svr_cfg.key(), &recv_buf[..recv_n])? {
            None => {
                error!("UDP packet too short, received length {}", recv_n);
                let err = io::Error::new(io::ErrorKind::InvalidData, "packet too short");
                return Err(err);
            }
            Some(b) => b,
        };
        // SERVER -> CLIENT protocol: ADDRESS + PAYLOAD
        let mut cur = Cursor::new(decrypt_buf);
        // FIXME: Address is ignored. Maybe useful in the future if we uses one common UdpSocket for communicate with remote server
        let _ = Address::read_from(&mut cur).await?;

        let mut payload = Vec::new();
        cur.read_to_end(&mut payload)?;

        #[cfg(feature = "local-flow-stat")]
        {
            context.local_flow_statistic().udp().incr_rx(recv_n as u64);
        }

        Ok(payload)
    }
}
