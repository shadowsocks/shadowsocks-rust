use std::{
    collections::{BTreeMap, HashMap},
    io::{self, ErrorKind},
    mem,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll, Waker},
    thread::{self, JoinHandle, Thread},
    time::Duration,
};

use log::{error, trace};
use ringbuf::{Consumer as RingBufferConsumer, Producer as RingBufferProducer, RingBuffer};
use shadowsocks::{net::TcpSocketOpts, relay::socks5::Address};
use smoltcp::{
    iface::{Interface, InterfaceBuilder, Routes, SocketHandle},
    phy::{DeviceCapabilities, Medium},
    socket::{TcpSocket, TcpSocketBuffer, TcpState},
    time::{Duration as SmolDuration, Instant as SmolInstant},
    wire::{IpAddress, IpCidr, Ipv4Address, Ipv6Address, TcpPacket},
};
use spin::Mutex as SpinMutex;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc,
};

use crate::local::{
    context::ServiceContext,
    loadbalancing::PingBalancer,
    net::AutoProxyClientStream,
    utils::{establish_tcp_tunnel, to_ipv4_mapped},
};

use super::virt_device::VirtTunDevice;

// NOTE: Default buffer could contain 20 AEAD packets
const DEFAULT_TCP_SEND_BUFFER_SIZE: u32 = 0x3FFF * 20;
const DEFAULT_TCP_RECV_BUFFER_SIZE: u32 = 0x3FFF * 20;

struct TcpSocketControl {
    send_waker: SpinMutex<Option<Waker>>,
    recv_waker: SpinMutex<Option<Waker>>,
    is_closed: AtomicBool,
}

struct ManagerNotify {
    thread: Thread,
}

impl ManagerNotify {
    fn new(thread: Thread) -> ManagerNotify {
        ManagerNotify { thread }
    }

    fn notify(&self) {
        self.thread.unpark();
    }
}

struct TcpSocketManager {
    iface: Interface<'static, VirtTunDevice>,
    sockets: HashMap<SocketHandle, TcpSocketControlBlock>,
    socket_creation_rx: mpsc::UnboundedReceiver<TcpSocketCreation>,
}

type SharedTcpConnectionControl = Arc<TcpSocketControl>;

struct TcpSocketControlBlock {
    control: SharedTcpConnectionControl,
    send_buffer_consumer: RingBufferConsumer<u8>,
    recv_buffer_producer: RingBufferProducer<u8>,
}

struct TcpSocketCreation {
    control_block: TcpSocketControlBlock,
    socket: TcpSocket<'static>,
}

struct TcpConnection {
    control: SharedTcpConnectionControl,
    manager_notify: Arc<ManagerNotify>,
    send_buffer_producer: RingBufferProducer<u8>,
    recv_buffer_consumer: RingBufferConsumer<u8>,
}

impl Drop for TcpConnection {
    fn drop(&mut self) {
        self.control.is_closed.store(true, Ordering::Release);
    }
}

impl TcpConnection {
    fn new(
        socket: TcpSocket<'static>,
        socket_creation_tx: &mpsc::UnboundedSender<TcpSocketCreation>,
        manager_notify: Arc<ManagerNotify>,
        tcp_opts: &TcpSocketOpts,
    ) -> TcpConnection {
        let send_buffer_size = tcp_opts.send_buffer_size.unwrap_or(DEFAULT_TCP_SEND_BUFFER_SIZE);
        let recv_buffer_size = tcp_opts.recv_buffer_size.unwrap_or(DEFAULT_TCP_RECV_BUFFER_SIZE);

        let send_buffer = RingBuffer::new(send_buffer_size as usize);
        let recv_buffer = RingBuffer::new(recv_buffer_size as usize);

        let (send_buffer_producer, send_buffer_consumer) = send_buffer.split();
        let (recv_buffer_producer, recv_buffer_consumer) = recv_buffer.split();

        let control = Arc::new(TcpSocketControl {
            send_waker: SpinMutex::new(None),
            recv_waker: SpinMutex::new(None),
            is_closed: AtomicBool::new(false),
        });

        let control_block = TcpSocketControlBlock {
            control: control.clone(),
            send_buffer_consumer,
            recv_buffer_producer,
        };

        let _ = socket_creation_tx.send(TcpSocketCreation { control_block, socket });

        TcpConnection {
            control,
            manager_notify,
            send_buffer_producer,
            recv_buffer_consumer,
        }
    }
}

impl AsyncRead for TcpConnection {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let TcpConnection {
            ref control,
            ref manager_notify,
            ref mut recv_buffer_consumer,
            ..
        } = *self;

        // If socket is already closed, just return EOF directly.
        if control.is_closed.load(Ordering::Acquire) {
            return Ok(()).into();
        }

        // Read from buffer

        let recv_buf = unsafe { mem::transmute::<_, &mut [u8]>(buf.unfilled_mut()) };
        let mut n = recv_buffer_consumer.pop_slice(recv_buf);
        if n == 0 {
            // Nothing could be read. Wait for notify.
            let mut recv_waker = control.recv_waker.lock();

            // Double check.
            if control.is_closed.load(Ordering::Acquire) {
                return Ok(()).into();
            }

            n = recv_buffer_consumer.pop_slice(recv_buf);
            if n == 0 {
                if let Some(old_waker) = recv_waker.replace(cx.waker().clone()) {
                    if !old_waker.will_wake(cx.waker()) {
                        old_waker.wake();
                    }
                }

                return Poll::Pending;
            }
        }

        buf.advance(n);

        if recv_buffer_consumer.is_empty() {
            manager_notify.notify();
        }
        Ok(()).into()
    }
}

impl AsyncWrite for TcpConnection {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let TcpConnection {
            ref control,
            ref manager_notify,
            ref mut send_buffer_producer,
            ..
        } = *self;

        // If socket is closed. EPIPE.
        if control.is_closed.load(Ordering::Acquire) {
            return Err(io::ErrorKind::BrokenPipe.into()).into();
        }

        // Write to buffer

        let mut n = send_buffer_producer.push_slice(buf);
        if n == 0 {
            // Nothing could be write. Wait for notify.
            let mut send_waker = control.send_waker.lock();

            // Double check.
            if control.is_closed.load(Ordering::Acquire) {
                return Err(io::ErrorKind::BrokenPipe.into()).into();
            }

            n = send_buffer_producer.push_slice(buf);
            if n == 0 {
                if let Some(old_waker) = send_waker.replace(cx.waker().clone()) {
                    if !old_waker.will_wake(cx.waker()) {
                        old_waker.wake();
                    }
                }

                return Poll::Pending;
            }
        }

        if send_buffer_producer.is_full() {
            manager_notify.notify();
        }
        Ok(n).into()
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Ok(()).into()
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.control.is_closed.load(Ordering::Acquire) {
            return Ok(()).into();
        }

        self.control.is_closed.store(true, Ordering::Release);
        Ok(()).into()
    }
}

pub struct TcpTun {
    context: Arc<ServiceContext>,
    manager_handle: Option<JoinHandle<()>>,
    manager_notify: Arc<ManagerNotify>,
    manager_socket_creation_tx: mpsc::UnboundedSender<TcpSocketCreation>,
    manager_running: Arc<AtomicBool>,
    balancer: PingBalancer,
    iface_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    iface_tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl Drop for TcpTun {
    fn drop(&mut self) {
        self.manager_running.store(false, Ordering::Relaxed);
        let _ = self.manager_handle.take().unwrap().join();
    }
}

impl TcpTun {
    pub fn new(context: Arc<ServiceContext>, balancer: PingBalancer, mtu: u32) -> TcpTun {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = mtu as usize;

        let (virt, iface_rx, iface_tx) = VirtTunDevice::new(capabilities);

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

        let (manager_socket_creation_tx, manager_socket_creation_rx) = mpsc::unbounded_channel();
        let mut manager = TcpSocketManager {
            iface,
            sockets: HashMap::new(),
            socket_creation_rx: manager_socket_creation_rx,
        };

        let manager_running = Arc::new(AtomicBool::new(true));

        let manager_handle = {
            let manager_running = manager_running.clone();

            thread::spawn(move || {
                let TcpSocketManager {
                    ref mut iface,
                    ref mut sockets,
                    ref mut socket_creation_rx,
                    ..
                } = manager;

                while manager_running.load(Ordering::Relaxed) {
                    while let Ok(TcpSocketCreation { control_block, socket }) = socket_creation_rx.try_recv() {
                        let handle = iface.add_socket(socket);
                        sockets.insert(handle, control_block);
                    }

                    let before_poll = SmolInstant::now();
                    let updated_sockets = match iface.poll(before_poll) {
                        Ok(u) => u,
                        Err(err) => {
                            error!("VirtDevice::poll error: {}", err);
                            false
                        }
                    };

                    if updated_sockets {
                        trace!("VirtDevice::poll costed {}", SmolInstant::now() - before_poll);
                    }

                    // Check all the sockets' status
                    let mut sockets_to_remove = Vec::new();

                    for (socket_handle, control_block) in sockets.iter_mut() {
                        let socket_handle = socket_handle.clone();
                        let socket = iface.get_socket::<TcpSocket>(socket_handle);

                        let TcpSocketControlBlock {
                            control,
                            send_buffer_consumer,
                            recv_buffer_producer,
                        } = control_block;

                        #[inline]
                        fn close_socket_control(control: &TcpSocketControl) {
                            control.is_closed.store(true, Ordering::Release);
                            if let Some(waker) = control.send_waker.lock().take() {
                                waker.wake();
                            }
                            if let Some(waker) = control.recv_waker.lock().take() {
                                waker.wake();
                            }
                        }

                        if !socket.is_open() || socket.state() == TcpState::Closed {
                            sockets_to_remove.push(socket_handle);
                            close_socket_control(control);
                            continue;
                        }

                        if control.is_closed.load(Ordering::Acquire) {
                            // Close the socket.
                            socket.close();
                            // sockets_to_remove.push(socket_handle);
                            // close_socket_control(&mut *control);
                            continue;
                        }

                        // Check if readable
                        let mut has_received = false;
                        while socket.can_recv() && !recv_buffer_producer.is_full() {
                            let result = socket.recv(|buffer| {
                                let n = recv_buffer_producer.push_slice(buffer);
                                (n, n)
                            });

                            match result {
                                Ok(n) => {
                                    has_received = n != 0;
                                }
                                Err(err) => {
                                    error!("socket recv error: {}", err);
                                    sockets_to_remove.push(socket_handle);
                                    close_socket_control(control);
                                    break;
                                }
                            }
                        }

                        if has_received {
                            let mut recv_waker = control.recv_waker.lock();
                            if let Some(waker) = recv_waker.take() {
                                waker.wake();
                            }
                        }

                        // Check if writable
                        let mut has_sent = false;
                        while socket.can_send() && !send_buffer_consumer.is_empty() {
                            let result = socket.send(|buffer| {
                                let n = send_buffer_consumer.pop_slice(buffer);
                                (n, n)
                            });

                            match result {
                                Ok(n) => {
                                    has_sent = n != 0;
                                }
                                Err(err) => {
                                    error!("socket send error: {}", err);
                                    sockets_to_remove.push(socket_handle);
                                    close_socket_control(control);
                                    break;
                                }
                            }
                        }

                        if has_sent {
                            let mut send_waker = control.send_waker.lock();
                            if let Some(waker) = send_waker.take() {
                                waker.wake();
                            }
                        }
                    }

                    for socket_handle in sockets_to_remove {
                        sockets.remove(&socket_handle);
                        iface.remove_socket(socket_handle);
                    }

                    let next_duration = iface.poll_delay(before_poll).unwrap_or(SmolDuration::from_millis(5));
                    if next_duration != SmolDuration::ZERO {
                        thread::park_timeout(Duration::from(next_duration));
                    }
                }

                trace!("VirtDevice::poll thread exited");
            })
        };

        let manager_notify = Arc::new(ManagerNotify::new(manager_handle.thread().clone()));

        TcpTun {
            context,
            manager_handle: Some(manager_handle),
            manager_notify,
            manager_socket_creation_tx,
            manager_running,
            balancer,
            iface_rx,
            iface_tx,
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

            let send_buffer_size = accept_opts.tcp.send_buffer_size.unwrap_or(DEFAULT_TCP_SEND_BUFFER_SIZE);
            let recv_buffer_size = accept_opts.tcp.recv_buffer_size.unwrap_or(DEFAULT_TCP_RECV_BUFFER_SIZE);

            let mut socket = TcpSocket::new(
                TcpSocketBuffer::new(vec![0u8; recv_buffer_size as usize]),
                TcpSocketBuffer::new(vec![0u8; send_buffer_size as usize]),
            );
            socket.set_keep_alive(accept_opts.tcp.keepalive.map(From::from));
            // FIXME: It should follow system's setting. 7200 is Linux's default.
            socket.set_timeout(Some(SmolDuration::from_secs(7200)));
            // NO ACK delay
            // socket.set_ack_delay(None);

            if let Err(err) = socket.listen(dst_addr) {
                return Err(io::Error::new(ErrorKind::Other, err));
            }

            trace!("created TCP connection for {} <-> {}", src_addr, dst_addr);

            let connection = TcpConnection::new(
                socket,
                &self.manager_socket_creation_tx,
                self.manager_notify.clone(),
                &accept_opts.tcp,
            );

            // establish a tunnel
            let context = self.context.clone();
            let balancer = self.balancer.clone();
            tokio::spawn(async move {
                if let Err(err) = handle_redir_client(context, balancer, connection, src_addr, dst_addr).await {
                    error!("TCP tunnel failure, {} <-> {}, error: {}", src_addr, dst_addr, err);
                }
            });
        }

        Ok(())
    }

    pub async fn drive_interface_state(&mut self, frame: &[u8]) {
        if let Err(..) = self.iface_tx.send(frame.to_vec()) {
            panic!("interface send channel closed unexpectly");
        }

        // Wake up and poll the interface.
        self.manager_notify.notify();
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
