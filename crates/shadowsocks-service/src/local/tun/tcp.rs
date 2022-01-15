use std::{
    collections::BTreeMap,
    io::{self, ErrorKind},
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex as StdMutex},
    task::{Context, Poll},
    time::Duration as StdDuration,
};

use log::{error, trace};
use shadowsocks::relay::socks5::Address;
use smoltcp::{
    iface::{Interface, InterfaceBuilder, Routes, SocketHandle},
    phy::{DeviceCapabilities, Medium},
    socket::{TcpSocket, TcpSocketBuffer, TcpState},
    time::{Duration, Instant},
    wire::{IpAddress, IpCidr, Ipv4Address, Ipv6Address, TcpPacket},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{mpsc, Notify},
    task::JoinHandle,
    time,
};

use crate::local::{
    context::ServiceContext,
    loadbalancing::PingBalancer,
    net::AutoProxyClientStream,
    utils::{establish_tcp_tunnel, to_ipv4_mapped},
};

use super::virt_device::VirtTunDevice;

struct TcpSocketManager {
    iface: Interface<'static, VirtTunDevice>,
    manager_notify: Arc<Notify>,
}

impl TcpSocketManager {
    fn notify(&self) {
        self.manager_notify.notify_waiters();
    }
}

type SharedTcpSocketManager = Arc<StdMutex<TcpSocketManager>>;

struct TcpConnection {
    socket_handle: SocketHandle,
    manager: SharedTcpSocketManager,
}

impl Drop for TcpConnection {
    fn drop(&mut self) {
        let mut manager = self.manager.lock().unwrap();
        let socket = manager.iface.get_socket::<TcpSocket>(self.socket_handle);
        socket.close();
    }
}

impl TcpConnection {
    fn new(socket: TcpSocket<'static>, manager: SharedTcpSocketManager) -> TcpConnection {
        let socket_handle = {
            let mut manager = manager.lock().unwrap();
            manager.iface.add_socket(socket)
        };

        TcpConnection { socket_handle, manager }
    }
}

impl AsyncRead for TcpConnection {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut manager = self.manager.lock().unwrap();
        {
            let socket = manager.iface.get_socket::<TcpSocket>(self.socket_handle);
            if !socket.is_open() {
                return Ok(()).into();
            }

            if socket.can_recv() {
                let recv_buf = buf.initialize_unfilled();
                let n = match socket.recv_slice(recv_buf) {
                    Ok(n) => n,
                    Err(err) => return Err(io::Error::new(ErrorKind::Other, err)).into(),
                };
                buf.advance(n);
            } else {
                socket.register_recv_waker(cx.waker());
                return Poll::Pending;
            }
        }

        manager.notify();
        Ok(()).into()
    }
}

impl AsyncWrite for TcpConnection {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut manager = self.manager.lock().unwrap();
        let n = {
            let socket = manager.iface.get_socket::<TcpSocket>(self.socket_handle);
            if !socket.is_open() {
                return Err(ErrorKind::BrokenPipe.into()).into();
            }
            if socket.can_send() {
                match socket.send_slice(buf) {
                    Ok(n) => n,
                    Err(err) => return Err(io::Error::new(ErrorKind::Other, err)).into(),
                }
            } else {
                socket.register_send_waker(cx.waker());
                return Poll::Pending;
            }
        };

        manager.notify();
        Ok(n).into()
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Ok(()).into()
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut manager = self.manager.lock().unwrap();
        {
            let socket = manager.iface.get_socket::<TcpSocket>(self.socket_handle);
            // close the transmission half.
            if socket.is_open() {
                socket.close();
            }

            if socket.state() != TcpState::Closed {
                socket.register_send_waker(cx.waker());
                return Poll::Pending;
            }
        }
        manager.notify();
        Ok(()).into()
    }
}

pub struct TcpTun {
    context: Arc<ServiceContext>,
    manager: SharedTcpSocketManager,
    manager_handle: JoinHandle<()>,
    manager_notify: Arc<Notify>,
    balancer: PingBalancer,
    iface_rx: mpsc::UnboundedReceiver<Vec<u8>>,
}

impl Drop for TcpTun {
    fn drop(&mut self) {
        self.manager_handle.abort();
    }
}

impl TcpTun {
    pub fn new(context: Arc<ServiceContext>, balancer: PingBalancer, mtu: u32) -> TcpTun {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = mtu as usize;

        let (iface_tx, iface_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let virt = VirtTunDevice::new(capabilities, iface_tx);

        let iface_builder = InterfaceBuilder::new(virt, vec![]);
        let iface_ipaddrs = [
            IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0),
            IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 0),
        ];
        let mut iface_routes = Routes::new(BTreeMap::new());
        iface_routes
            .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1))
            .expect("IPv4 route");
        iface_routes
            .add_default_ipv6_route(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1))
            .expect("IPv6 route");
        let iface = iface_builder
            .any_ip(true)
            .ip_addrs(iface_ipaddrs)
            .routes(iface_routes)
            .finalize();

        let manager_notify = Arc::new(Notify::new());
        let manager = Arc::new(StdMutex::new(TcpSocketManager {
            iface,
            manager_notify: manager_notify.clone(),
        }));

        let manager_handle = {
            let manager = manager.clone();
            let manager_notify = manager_notify.clone();
            tokio::spawn(async move {
                loop {
                    let next_duration = {
                        let mut manager = manager.lock().unwrap();

                        if let Err(err) = manager.iface.poll(Instant::now()) {
                            error!("virtual device error: {}", err);
                        }

                        let next_duration = manager
                            .iface
                            .poll_delay(Instant::now())
                            .unwrap_or(Duration::from_millis(50));

                        next_duration
                    };

                    tokio::select! {
                        _ = time::sleep(StdDuration::from(next_duration)) => {}
                        _ = manager_notify.notified() => {}
                    }
                }
            })
        };

        TcpTun {
            context,
            manager,
            manager_handle,
            manager_notify,
            balancer,
            iface_rx,
        }
    }

    pub async fn handle_packet(
        &mut self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        tcp_packet: &TcpPacket<&[u8]>,
    ) -> io::Result<()> {
        // TCP first handshake packet, create a new Connection
        if tcp_packet.syn() && !tcp_packet.ack() {
            let accept_opts = self.context.accept_opts();
            let send_buffer_size = accept_opts.tcp.send_buffer_size.unwrap_or(4096);
            let recv_buffer_size = accept_opts.tcp.recv_buffer_size.unwrap_or(4096);

            let mut socket = TcpSocket::new(
                TcpSocketBuffer::new(vec![0u8; recv_buffer_size as usize]),
                TcpSocketBuffer::new(vec![0u8; send_buffer_size as usize]),
            );
            socket.set_ack_delay(None);
            if let Err(err) = socket.listen(dst_addr) {
                return Err(io::Error::new(ErrorKind::Other, err));
            }

            trace!("created TCP connection for {} <-> {}", src_addr, dst_addr);

            let connection = TcpConnection::new(socket, self.manager.clone());

            // establish a tunnel
            let context = self.context.clone();
            let balancer = self.balancer.clone();
            tokio::spawn(async move {
                if let Err(err) = handle_redir_client(context, balancer, connection, src_addr, dst_addr).await {
                    error!("TCP tunnel failure, {} <-> {}, error: {}", src_addr, dst_addr, err);
                }
            });

            // Wake up and poll the interface.
            self.manager_notify.notify_waiters();
        }

        Ok(())
    }

    pub fn drive_interface_state(&mut self, frame: &[u8]) {
        let mut manager = self.manager.lock().unwrap();
        manager.iface.device_mut().inject_packet(frame.to_vec());
    }

    pub async fn recv_packet(&mut self) -> Vec<u8> {
        match self.iface_rx.recv().await {
            Some(v) => v,
            None => unreachable!("channel closed unexpectedly"),
        }
    }
}

/// Established Client Transparent Proxy
///
/// This method must be called after handshaking with client (for example, socks5 handshaking)
async fn establish_client_tcp_redir<'a>(
    context: Arc<ServiceContext>,
    balancer: PingBalancer,
    mut stream: TcpConnection,
    peer_addr: SocketAddr,
    addr: &Address,
) -> io::Result<()> {
    let server = balancer.best_tcp_server();
    let svr_cfg = server.server_config();

    let mut remote = AutoProxyClientStream::connect(context, &server, addr).await?;

    establish_tcp_tunnel(svr_cfg, &mut stream, &mut remote, peer_addr, addr).await
}

async fn handle_redir_client(
    context: Arc<ServiceContext>,
    balancer: PingBalancer,
    s: TcpConnection,
    peer_addr: SocketAddr,
    mut daddr: SocketAddr,
) -> io::Result<()> {
    // Get forward address from socket
    //
    // Try to convert IPv4 mapped IPv6 address for dual-stack mode.
    if let SocketAddr::V6(ref a) = daddr {
        if let Some(v4) = to_ipv4_mapped(a.ip()) {
            daddr = SocketAddr::new(IpAddr::from(v4), a.port());
        }
    }
    let target_addr = Address::from(daddr);
    establish_client_tcp_redir(context, balancer, s, peer_addr, &target_addr).await
}
