//! Shadowsocks DNS relay local server
//!
//! This DNS server requires 2 upstream DNS servers, one for direct queries, and the other queries through shadowsocks proxy

use std::{
    cmp::Ordering,
    collections::HashSet,
    io::{self, ErrorKind},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use futures::{
    FutureExt,
    future::{self, Either},
};
use hickory_resolver::proto::{
    op::{Message, OpCode, Query, header::MessageType, response_code::ResponseCode},
    rr::{DNSClass, Name, RData, RecordType},
};
use log::{debug, error, info, trace, warn};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time,
};

use shadowsocks::{
    ServerAddr,
    config::Mode,
    net::TcpListener,
    relay::{Address, udprelay::MAXIMUM_UDP_PAYLOAD_SIZE},
};

use crate::{
    acl::AccessControl,
    local::{
        context::ServiceContext,
        loadbalancing::PingBalancer,
        net::{tcp::listener::create_standard_tcp_listener, udp::listener::create_standard_udp_listener},
    },
};

use super::{client_cache::DnsClientCache, config::NameServerAddr};

/// DNS Relay server builder
pub struct DnsBuilder {
    context: Arc<ServiceContext>,
    mode: Mode,
    local_addr: NameServerAddr,
    remote_addr: Address,
    bind_addr: ServerAddr,
    balancer: PingBalancer,
    client_cache_size: usize,
    #[cfg(target_os = "macos")]
    launchd_tcp_socket_name: Option<String>,
    #[cfg(target_os = "macos")]
    launchd_udp_socket_name: Option<String>,
}

impl DnsBuilder {
    /// Create a new DNS Relay server
    pub fn new(
        bind_addr: ServerAddr,
        local_addr: NameServerAddr,
        remote_addr: Address,
        balancer: PingBalancer,
        client_cache_size: usize,
    ) -> Self {
        let context = ServiceContext::new();
        Self::with_context(
            Arc::new(context),
            bind_addr,
            local_addr,
            remote_addr,
            balancer,
            client_cache_size,
        )
    }

    /// Create with an existed `context`
    pub fn with_context(
        context: Arc<ServiceContext>,
        bind_addr: ServerAddr,
        local_addr: NameServerAddr,
        remote_addr: Address,
        balancer: PingBalancer,
        client_cache_size: usize,
    ) -> Self {
        Self {
            context,
            mode: Mode::UdpOnly,
            local_addr,
            remote_addr,
            bind_addr,
            balancer,
            client_cache_size,
            #[cfg(target_os = "macos")]
            launchd_tcp_socket_name: None,
            #[cfg(target_os = "macos")]
            launchd_udp_socket_name: None,
        }
    }

    /// Set remote server mode
    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
    }

    /// macOS launchd activate socket
    #[cfg(target_os = "macos")]
    pub fn set_launchd_tcp_socket_name(&mut self, n: String) {
        self.launchd_tcp_socket_name = Some(n);
    }

    /// macOS launchd activate socket
    #[cfg(target_os = "macos")]
    pub fn set_launchd_udp_socket_name(&mut self, n: String) {
        self.launchd_udp_socket_name = Some(n);
    }

    /// Build DNS server
    pub async fn build(self) -> io::Result<Dns> {
        let client = Arc::new(DnsClient::new(
            self.context.clone(),
            self.balancer,
            self.mode,
            self.client_cache_size,
        ));

        let local_addr = Arc::new(self.local_addr);
        let remote_addr = Arc::new(self.remote_addr);

        let mut tcp_server = None;
        if self.mode.enable_tcp() {
            #[allow(unused_mut)]
            let mut builder = DnsTcpServerBuilder::new(
                self.context.clone(),
                self.bind_addr.clone(),
                local_addr.clone(),
                remote_addr.clone(),
                client.clone(),
            );

            #[cfg(target_os = "macos")]
            if let Some(s) = self.launchd_tcp_socket_name {
                builder.set_launchd_socket_name(s);
            }

            let server = builder.build().await?;
            tcp_server = Some(server);
        }

        let mut udp_server = None;
        if self.mode.enable_udp() {
            #[allow(unused_mut)]
            let mut builder = DnsUdpServerBuilder::new(self.context, self.bind_addr, local_addr, remote_addr, client);

            #[cfg(target_os = "macos")]
            if let Some(s) = self.launchd_udp_socket_name {
                builder.set_launchd_socket_name(s);
            }

            let server = builder.build().await?;
            udp_server = Some(server);
        }

        Ok(Dns { tcp_server, udp_server })
    }
}

struct DnsTcpServerBuilder {
    context: Arc<ServiceContext>,
    bind_addr: ServerAddr,
    local_addr: Arc<NameServerAddr>,
    remote_addr: Arc<Address>,
    client: Arc<DnsClient>,
    #[cfg(target_os = "macos")]
    launchd_socket_name: Option<String>,
}

impl DnsTcpServerBuilder {
    fn new(
        context: Arc<ServiceContext>,
        bind_addr: ServerAddr,
        local_addr: Arc<NameServerAddr>,
        remote_addr: Arc<Address>,
        client: Arc<DnsClient>,
    ) -> Self {
        Self {
            context,
            bind_addr,
            local_addr,
            remote_addr,
            client,
            #[cfg(target_os = "macos")]
            launchd_socket_name: None,
        }
    }

    /// macOS launchd activate socket
    #[cfg(target_os = "macos")]
    fn set_launchd_socket_name(&mut self, n: String) {
        self.launchd_socket_name = Some(n);
    }

    async fn build(self) -> io::Result<DnsTcpServer> {
        cfg_if::cfg_if! {
            if #[cfg(target_os = "macos")] {
                let listener = match self.launchd_socket_name {
                    Some(launchd_socket_name) => {
                        use tokio::net::TcpListener as TokioTcpListener;
                        use crate::net::launch_activate_socket::get_launch_activate_tcp_listener;

                        let std_listener = get_launch_activate_tcp_listener(&launchd_socket_name, true)?;
                        let tokio_listener = TokioTcpListener::from_std(std_listener)?;
                        TcpListener::from_listener(tokio_listener, self.context.accept_opts())?
                    } _ => {
                        create_standard_tcp_listener(&self.context, &self.bind_addr).await?
                    }
                };
            } else {
                let listener = create_standard_tcp_listener(&self.context, &self.bind_addr).await?;
            }
        }

        Ok(DnsTcpServer {
            listener,
            local_addr: self.local_addr,
            remote_addr: self.remote_addr,
            client: self.client,
        })
    }
}

/// DNS TCP server instance
pub struct DnsTcpServer {
    listener: TcpListener,
    local_addr: Arc<NameServerAddr>,
    remote_addr: Arc<Address>,
    client: Arc<DnsClient>,
}

impl DnsTcpServer {
    /// Get server local address
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Start serving
    pub async fn run(self) -> io::Result<()> {
        info!(
            "shadowsocks dns TCP listening on {}, local: {}, remote: {}",
            self.listener.local_addr()?,
            self.local_addr,
            self.remote_addr
        );

        loop {
            let (stream, peer_addr) = match self.listener.accept().await {
                Ok(s) => s,
                Err(err) => {
                    error!("accept failed with error: {}", err);
                    time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            tokio::spawn(Self::handle_tcp_stream(
                self.client.clone(),
                stream,
                peer_addr,
                self.local_addr.clone(),
                self.remote_addr.clone(),
            ));
        }
    }

    async fn handle_tcp_stream(
        client: Arc<DnsClient>,
        mut stream: TcpStream,
        peer_addr: SocketAddr,
        local_addr: Arc<NameServerAddr>,
        remote_addr: Arc<Address>,
    ) -> io::Result<()> {
        let mut length_buf = [0u8; 2];
        let mut message_buf = BytesMut::new();
        loop {
            match stream.read_exact(&mut length_buf).await {
                Ok(..) => {}
                Err(ref err) if err.kind() == ErrorKind::UnexpectedEof => {
                    break;
                }
                Err(err) => {
                    error!("udp tcp {} read length failed, error: {}", peer_addr, err);
                    return Err(err);
                }
            }

            let length = BigEndian::read_u16(&length_buf) as usize;

            message_buf.clear();
            message_buf.reserve(length);
            unsafe {
                message_buf.advance_mut(length);
            }

            match stream.read_exact(&mut message_buf).await {
                Ok(..) => {}
                Err(err) => {
                    error!("dns tcp {} read message failed, error: {}", peer_addr, err);
                    return Err(err);
                }
            }

            let message = match Message::from_vec(&message_buf) {
                Ok(m) => m,
                Err(err) => {
                    error!("dns tcp {} parse message failed, error: {}", peer_addr, err);
                    return Err(err.into());
                }
            };

            let respond_message = match client.resolve(message, &local_addr, &remote_addr).await {
                Ok(m) => m,
                Err(err) => {
                    error!("dns tcp {} lookup error: {}", peer_addr, err);
                    return Err(err);
                }
            };

            let mut buf = respond_message.to_vec()?;
            let length = buf.len();
            buf.resize(length + 2, 0);
            buf.copy_within(..length, 2);
            BigEndian::write_u16(&mut buf[..2], length as u16);

            stream.write_all(&buf).await?;
        }

        trace!("dns tcp connection {} closed", peer_addr);

        Ok(())
    }
}

struct DnsUdpServerBuilder {
    context: Arc<ServiceContext>,
    bind_addr: ServerAddr,
    local_addr: Arc<NameServerAddr>,
    remote_addr: Arc<Address>,
    client: Arc<DnsClient>,
    #[cfg(target_os = "macos")]
    launchd_socket_name: Option<String>,
}

impl DnsUdpServerBuilder {
    fn new(
        context: Arc<ServiceContext>,
        bind_addr: ServerAddr,
        local_addr: Arc<NameServerAddr>,
        remote_addr: Arc<Address>,
        client: Arc<DnsClient>,
    ) -> Self {
        Self {
            context,
            bind_addr,
            local_addr,
            remote_addr,
            client,
            #[cfg(target_os = "macos")]
            launchd_socket_name: None,
        }
    }

    /// macOS launchd activate socket
    #[cfg(target_os = "macos")]
    fn set_launchd_socket_name(&mut self, n: String) {
        self.launchd_socket_name = Some(n);
    }

    async fn build(self) -> io::Result<DnsUdpServer> {
        cfg_if::cfg_if! {
            if #[cfg(target_os = "macos")] {
                let socket = match self.launchd_socket_name { Some(launchd_socket_name) => {
                    use tokio::net::UdpSocket as TokioUdpSocket;
                    use crate::net::launch_activate_socket::get_launch_activate_udp_socket;

                    let std_socket = get_launch_activate_udp_socket(&launchd_socket_name, true)?;
                    TokioUdpSocket::from_std(std_socket)?
                } _ => {
                    create_standard_udp_listener(&self.context, &self.bind_addr).await?.into()
                }};
            } else {
                let socket = create_standard_udp_listener(&self.context, &self.bind_addr).await?.into();
            }
        }

        Ok(DnsUdpServer {
            listener: Arc::new(socket),
            local_addr: self.local_addr,
            remote_addr: self.remote_addr,
            client: self.client,
        })
    }
}

/// DNS UDP server instance
pub struct DnsUdpServer {
    listener: Arc<UdpSocket>,
    local_addr: Arc<NameServerAddr>,
    remote_addr: Arc<Address>,
    client: Arc<DnsClient>,
}

impl DnsUdpServer {
    /// Get server local address
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Start serving
    pub async fn run(self) -> io::Result<()> {
        info!(
            "shadowsocks dns UDP listening on {}, local: {}, remote: {}",
            self.listener.local_addr()?,
            self.local_addr,
            self.remote_addr
        );

        let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        loop {
            let (n, peer_addr) = match self.listener.recv_from(&mut buffer).await {
                Ok(s) => s,
                Err(err) => {
                    error!("udp server recv_from failed with error: {}", err);
                    time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            let data = &buffer[..n];

            let message = match Message::from_vec(data) {
                Ok(m) => m,
                Err(err) => {
                    error!("dns udp {} query message parse error: {}", peer_addr, err);
                    continue;
                }
            };

            tokio::spawn(Self::handle_udp_packet(
                self.client.clone(),
                self.listener.clone(),
                peer_addr,
                message,
                self.local_addr.clone(),
                self.remote_addr.clone(),
            ));
        }
    }

    async fn handle_udp_packet(
        client: Arc<DnsClient>,
        listener: Arc<UdpSocket>,
        peer_addr: SocketAddr,
        message: Message,
        local_addr: Arc<NameServerAddr>,
        remote_addr: Arc<Address>,
    ) -> io::Result<()> {
        let respond_message = match client.resolve(message, &local_addr, &remote_addr).await {
            Ok(m) => m,
            Err(err) => {
                error!("dns udp {} lookup failed, error: {}", peer_addr, err);
                return Err(err);
            }
        };

        let buf = respond_message.to_vec()?;
        listener.send_to(&buf, peer_addr).await?;

        Ok(())
    }
}

/// DNS Relay server
pub struct Dns {
    tcp_server: Option<DnsTcpServer>,
    udp_server: Option<DnsUdpServer>,
}

impl Dns {
    /// Get TCP server instance
    pub fn tcp_server(&self) -> Option<&DnsTcpServer> {
        self.tcp_server.as_ref()
    }

    /// Get UDP server instance
    pub fn udp_server(&self) -> Option<&DnsUdpServer> {
        self.udp_server.as_ref()
    }

    /// Run server
    pub async fn run(self) -> io::Result<()> {
        let mut vfut = Vec::new();

        if let Some(tcp_server) = self.tcp_server {
            vfut.push(tcp_server.run().boxed());
        }

        if let Some(udp_server) = self.udp_server {
            // NOTE: SOCKS 5 RFC requires TCP handshake for UDP ASSOCIATE command
            // But here we can start a standalone UDP SOCKS 5 relay server, for special use cases
            vfut.push(udp_server.run().boxed());
        }

        let (res, ..) = future::select_all(vfut).await;
        res
    }
}

fn should_forward_by_ptr_name(acl: &AccessControl, name: &Name) -> bool {
    let mut iter = name.iter().rev();
    let mut next = || match iter.next() {
        Some(label) => std::str::from_utf8(label).unwrap_or("*"),
        None => "0", // zero fill the missing labels
    };
    if !"arpa".eq_ignore_ascii_case(next()) {
        return acl.is_default_in_proxy_list();
    }
    match &next().to_ascii_lowercase()[..] {
        "in-addr" => {
            let mut octets: [u8; 4] = [0; 4];
            for octet in octets.iter_mut() {
                match next().parse() {
                    Ok(result) => *octet = result,
                    Err(_) => return acl.is_default_in_proxy_list(),
                }
            }
            acl.check_ip_in_proxy_list(&IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])))
        }
        "ip6" => {
            let mut segments: [u16; 8] = [0; 8];
            for segment in segments.iter_mut() {
                match u16::from_str_radix(&[next(), next(), next(), next()].concat(), 16) {
                    Ok(result) => *segment = result,
                    Err(_) => return acl.is_default_in_proxy_list(),
                }
            }
            acl.check_ip_in_proxy_list(&IpAddr::V6(Ipv6Addr::new(
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                segments[4],
                segments[5],
                segments[6],
                segments[7],
            )))
        }
        _ => acl.is_default_in_proxy_list(),
    }
}

fn check_name_in_proxy_list(acl: &AccessControl, name: &Name) -> Option<bool> {
    if name.is_fqdn() {
        // convert to ASCII representation
        let mut name = name.to_ascii();
        name.make_ascii_lowercase();
        acl.check_ascii_host_in_proxy_list(&name)
    } else {
        // unconditionally use default for PQDNs
        Some(acl.is_default_in_proxy_list())
    }
}

/// given the query, determine whether remote/local query should be used, or inconclusive
fn should_forward_by_query(context: &ServiceContext, balancer: &PingBalancer, query: &Query) -> Option<bool> {
    // No server was configured, then always resolve with local
    if balancer.is_empty() {
        return Some(false);
    }

    // Check if we are trying to make queries for remote servers
    //
    // This happens normally because VPN or TUN device receives DNS queries from local servers' plugins
    // https://github.com/shadowsocks/shadowsocks-android/issues/2722
    for server in balancer.servers() {
        let svr_cfg = server.server_config();
        if let ServerAddr::DomainName(dn, ..) = svr_cfg.addr() {
            // Convert domain name to `Name`
            // Ignore it if error occurs
            if let Ok(mut name) = Name::from_str(dn) {
                // cmp will handle FQDN in case insensitive way
                if let Ordering::Equal = query.name().cmp(&name) {
                    // It seems that query is for this server, just bypass it to local resolver
                    trace!("DNS querying name {} of server {:?}", query.name(), svr_cfg);
                    return Some(false);
                }
                // test it again with fqdn set
                name.set_fqdn(true);
                if let Ordering::Equal = query.name().cmp(&name) {
                    trace!("DNS querying name {} of server {:?}", query.name(), svr_cfg);
                    return Some(false);
                }
            }
        }
    }

    if let Some(acl) = context.acl() {
        if query.query_class() != DNSClass::IN {
            // unconditionally use default for all non-IN queries
            Some(acl.is_default_in_proxy_list())
        } else if query.query_type() == RecordType::PTR {
            Some(should_forward_by_ptr_name(acl, query.name()))
        } else {
            let result = check_name_in_proxy_list(acl, query.name());
            if result.is_none() && acl.is_ip_empty() && acl.is_host_empty() {
                Some(acl.is_default_in_proxy_list())
            } else {
                result
            }
        }
    } else {
        Some(true)
    }
}

/// given the local response, determine whether remote response should be used instead
fn should_forward_by_response(
    acl: Option<&AccessControl>,
    local_response: &io::Result<Message>,
    query: &Query,
) -> bool {
    if let Some(acl) = acl {
        if let Ok(local_response) = local_response {
            let mut names = HashSet::new();
            names.insert(query.name());
            macro_rules! examine_name {
                ($name:expr_2021, $is_answer:expr_2021) => {{
                    names.insert($name);
                    if $is_answer {
                        if let Some(value) = check_name_in_proxy_list(acl, $name) {
                            value
                        } else {
                            acl.is_default_in_proxy_list()
                        }
                    } else {
                        acl.is_default_in_proxy_list()
                    }
                }};
            }
            macro_rules! examine_record {
                ($rec:ident, $is_answer:expr_2021) => {
                    if let RData::CNAME(name) = $rec.data() {
                        if $is_answer {
                            if let Some(value) = check_name_in_proxy_list(acl, name) {
                                return value;
                            }
                        }
                        names.insert(name);
                        continue;
                    }
                    if $is_answer && !query.query_type().is_any() && $rec.record_type() != query.query_type() {
                        warn!(
                            "local DNS response has inconsistent answer type {} for query {}",
                            $rec.record_type(),
                            query
                        );
                        return true;
                    }
                    let forward = match $rec.data() {
                        RData::A(ip) => acl.check_ip_in_proxy_list(&IpAddr::V4((*ip).into())),
                        RData::AAAA(ip) => acl.check_ip_in_proxy_list(&IpAddr::V6((*ip).into())),
                        // MX records cause type A additional section processing for the host specified by EXCHANGE.
                        RData::MX(mx) => examine_name!(mx.exchange(), $is_answer),
                        // NS records cause both the usual additional section processing to locate a type A record...
                        RData::NS(name) => examine_name!(name, $is_answer),
                        RData::PTR(_) => unreachable!(),
                        _ => acl.is_default_in_proxy_list(),
                    };
                    if !forward {
                        return false;
                    }
                };
            }
            for rec in local_response.answers() {
                if !names.contains(rec.name()) {
                    warn!(
                        "local DNS response contains unexpected name {} for query {}",
                        rec.name(),
                        query
                    );
                    return true;
                }
                examine_record!(rec, true);
            }
            for rec in local_response.additionals() {
                if names.contains(rec.name()) {
                    examine_record!(rec, false);
                }
            }
        }
        true
    } else {
        unreachable!()
    }
}

struct DnsClient {
    context: Arc<ServiceContext>,
    client_cache: DnsClientCache,
    mode: Mode,
    balancer: PingBalancer,
    attempts: usize,
}

impl DnsClient {
    fn new(context: Arc<ServiceContext>, balancer: PingBalancer, mode: Mode, client_cache_size: usize) -> Self {
        Self {
            context,
            client_cache: DnsClientCache::new(client_cache_size),
            mode,
            balancer,
            attempts: 2,
        }
    }

    async fn resolve(
        &self,
        request: Message,
        local_addr: &NameServerAddr,
        remote_addr: &Address,
    ) -> io::Result<Message> {
        let mut message = Message::new();
        message.set_id(request.id());
        message.set_recursion_desired(true);
        message.set_recursion_available(true);
        message.set_message_type(MessageType::Response);

        if !request.recursion_desired() {
            // RD is required by default. Otherwise it may not get valid respond from remote servers

            message.set_recursion_desired(false);
            message.set_response_code(ResponseCode::NotImp);
        } else if request.op_code() != OpCode::Query || request.message_type() != MessageType::Query {
            // Other ops are not supported

            message.set_response_code(ResponseCode::NotImp);
        } else if request.query_count() > 0 {
            // Make queries according to ACL rules

            let (r, forward) = self.acl_lookup(&request.queries()[0], local_addr, remote_addr).await;
            if let Ok(result) = r {
                for rec in result.answers() {
                    trace!("dns answer: {:?}", rec);
                    match rec.data() {
                        RData::A(ip) => {
                            self.context
                                .add_to_reverse_lookup_cache(Ipv4Addr::from(*ip).into(), forward)
                                .await
                        }
                        RData::AAAA(ip) => {
                            self.context
                                .add_to_reverse_lookup_cache(Ipv6Addr::from(*ip).into(), forward)
                                .await
                        }
                        _ => (),
                    }
                }
                message = result;
                message.set_id(request.id());
            } else {
                message.set_response_code(ResponseCode::ServFail);
            }
        }
        Ok(message)
    }

    async fn acl_lookup(
        &self,
        query: &Query,
        local_addr: &NameServerAddr,
        remote_addr: &Address,
    ) -> (io::Result<Message>, bool) {
        // Start querying name servers
        debug!("DNS lookup {:?} {}", query.query_type(), query.name());

        match should_forward_by_query(&self.context, &self.balancer, query) {
            Some(true) => {
                let remote_response = self.lookup_remote(query, remote_addr).await;
                trace!("pick remote response (query): {:?}", remote_response);
                return (remote_response, true);
            }
            Some(false) => {
                let local_response = self.lookup_local(query, local_addr).await;
                trace!("pick local response (query): {:?}", local_response);
                return (local_response, false);
            }
            None => (),
        }

        let decider = async {
            let local_response = self.lookup_local(query, local_addr).await;
            if should_forward_by_response(self.context.acl(), &local_response, query) {
                None
            } else {
                Some(local_response)
            }
        };

        let remote_response_fut = self.lookup_remote(query, remote_addr);
        tokio::pin!(remote_response_fut, decider);

        let mut use_remote = false;
        let mut remote_response = None;
        loop {
            tokio::select! {
                response = &mut remote_response_fut, if remote_response.is_none() => {
                    if use_remote {
                        trace!("pick remote response (response): {:?}", response);
                        return (response, true);
                    } else {
                        remote_response = Some(response);
                    }
                }
                decision = &mut decider, if !use_remote => {
                    if let Some(local_response) = decision {
                        trace!("pick local response (response): {:?}", local_response);
                        return (local_response, false);
                    } else if let Some(remote_response) = remote_response {
                        trace!("pick remote response (response): {:?}", remote_response);
                        return (remote_response, true);
                    } else {
                        use_remote = true;
                    }
                }
                else => unreachable!(),
            }
        }
    }

    async fn lookup_remote(&self, query: &Query, remote_addr: &Address) -> io::Result<Message> {
        let mut last_err = io::Error::new(ErrorKind::InvalidData, "resolve empty");

        for _ in 0..self.attempts {
            match self.lookup_remote_inner(query, remote_addr).await {
                Ok(m) => {
                    return Ok(m);
                }
                Err(err) => last_err = err,
            }
        }

        Err(last_err)
    }

    async fn lookup_remote_inner(&self, query: &Query, remote_addr: &Address) -> io::Result<Message> {
        let mut message = Message::new();
        message.set_id(rand::random());
        message.set_recursion_desired(true);
        message.add_query(query.clone());

        // Query UDP and TCP

        match self.mode {
            Mode::TcpOnly => {
                let server = self.balancer.best_tcp_server();
                self.client_cache
                    .lookup_remote(&self.context, server.server_config(), remote_addr, message, false)
                    .await
                    .map_err(From::from)
            }
            Mode::UdpOnly => {
                let server = self.balancer.best_udp_server();
                self.client_cache
                    .lookup_remote(&self.context, server.server_config(), remote_addr, message, true)
                    .await
                    .map_err(From::from)
            }
            Mode::TcpAndUdp => {
                // Query TCP & UDP simutaneously

                let message2 = message.clone();
                let tcp_fut = async {
                    // For most cases UDP query will return in 1s,
                    // Then this future will be disabled and have no effect
                    //
                    // Randomly choose from 500ms ~ 1.5s for preventing obvious request pattern
                    let sleep_time = rand::random_range(500..=1500);
                    time::sleep(Duration::from_millis(sleep_time)).await;

                    let server = self.balancer.best_tcp_server();
                    self.client_cache
                        .lookup_remote(&self.context, server.server_config(), remote_addr, message2, false)
                        .await
                };
                let udp_fut = async {
                    let server = self.balancer.best_udp_server();
                    self.client_cache
                        .lookup_remote(&self.context, server.server_config(), remote_addr, message, true)
                        .await
                };

                tokio::pin!(tcp_fut);
                tokio::pin!(udp_fut);

                match future::select(tcp_fut, udp_fut).await {
                    Either::Left((res, next)) => match res {
                        Ok(o) => Ok(o),
                        Err(..) => next.await.map_err(From::from),
                    },
                    Either::Right((res, next)) => match res {
                        Ok(o) => Ok(o),
                        Err(..) => next.await.map_err(From::from),
                    },
                }
            }
        }
    }

    async fn lookup_local(&self, query: &Query, local_addr: &NameServerAddr) -> io::Result<Message> {
        let mut last_err = io::Error::new(ErrorKind::InvalidData, "resolve empty");

        for _ in 0..self.attempts {
            match self.lookup_local_inner(query, local_addr).await {
                Ok(m) => {
                    return Ok(m);
                }
                Err(err) => last_err = err,
            }
        }

        Err(last_err)
    }

    async fn lookup_local_inner(&self, query: &Query, local_addr: &NameServerAddr) -> io::Result<Message> {
        let mut message = Message::new();
        message.set_id(rand::random());
        message.set_recursion_desired(true);
        message.add_query(query.clone());

        match *local_addr {
            NameServerAddr::SocketAddr(ns) => {
                // Query UDP then TCP

                let udp_query =
                    self.client_cache
                        .lookup_local(ns, message.clone(), self.context.connect_opts_ref(), true);
                let tcp_query = async move {
                    // Send TCP query after 500ms, because UDP will always return faster than TCP, there is no need to send queries simutaneously
                    time::sleep(Duration::from_millis(500)).await;

                    self.client_cache
                        .lookup_local(ns, message, self.context.connect_opts_ref(), false)
                        .await
                };

                tokio::pin!(udp_query);
                tokio::pin!(tcp_query);

                match future::select(udp_query, tcp_query).await {
                    Either::Left((Ok(m), ..)) => Ok(m),
                    Either::Left((Err(..), next)) => next.await.map_err(From::from),
                    Either::Right((Ok(m), ..)) => Ok(m),
                    Either::Right((Err(..), next)) => next.await.map_err(From::from),
                }
            }
            #[cfg(unix)]
            NameServerAddr::UnixSocketAddr(ref path) => self
                .client_cache
                .lookup_unix_stream(path, message)
                .await
                .map_err(From::from),
        }
    }
}
