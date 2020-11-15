use std::{
    collections::HashSet,
    fmt::Display,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use log::{debug, error, info, trace, warn};
use tokio::{net::TcpListener, select, time};
use trust_dns_proto::{
    op::{header::MessageType, response_code::ResponseCode, Message, OpCode, Query},
    rr::{DNSClass, Name, RData, RecordType},
};

use crate::{
    acl::AccessControl,
    config::ConfigType,
    context::SharedContext,
    relay::{sys::create_udp_socket, utils::try_timeout},
};

use self::upstream::{ProxyUpstream, Upstream};

pub(crate) mod upstream;

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
        // remove the last dot from FQDN
        let mut name = name.to_ascii();
        name.pop();
        acl.check_host_in_proxy_list(&name)
    } else {
        // unconditionally use default for PQDNs
        Some(acl.is_default_in_proxy_list())
    }
}

/// given the query, determine whether remote/local query should be used, or inconclusive
fn should_forward_by_query(acl: Option<&AccessControl>, query: &Query) -> Option<bool> {
    if let Some(acl) = acl {
        if query.query_class() != DNSClass::IN {
            // unconditionally use default for all non-IN queries
            Some(acl.is_default_in_proxy_list())
        } else if query.query_type() == RecordType::PTR {
            Some(should_forward_by_ptr_name(acl, query.name()))
        } else {
            let result = check_name_in_proxy_list(acl, query.name());
            if result == None && acl.is_ip_empty() && acl.is_host_empty() {
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
        if let Ok(ref local_response) = local_response {
            let mut names = HashSet::new();
            names.insert(query.name());
            macro_rules! examine_name {
                ($name:expr, $is_answer:expr) => {{
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
                ($rec:ident, $is_answer:expr) => {
                    if let RData::CNAME(ref name) = $rec.rdata() {
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
                    let forward = match $rec.rdata() {
                        RData::A(ref ip) => acl.check_ip_in_proxy_list(&IpAddr::V4(*ip)),
                        RData::AAAA(ref ip) => acl.check_ip_in_proxy_list(&IpAddr::V6(*ip)),
                        // MX records cause type A additional section processing for the host specified by EXCHANGE.
                        RData::MX(ref mx) => examine_name!(mx.exchange(), $is_answer),
                        // NS records cause both the usual additional section processing to locate a type A record...
                        RData::NS(ref name) => examine_name!(name, $is_answer),
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

struct DnsRelay<Remote>
where
    Remote: Upstream,
{
    context: SharedContext,
    remote_upstream: Remote,
}

impl<Remote> DnsRelay<Remote>
where
    Remote: Upstream,
{
    fn new(context: SharedContext, remote_upstream: Remote) -> DnsRelay<Remote> {
        DnsRelay {
            context,
            remote_upstream,
        }
    }

    async fn acl_lookup(&self, query: &Query) -> (io::Result<Message>, bool) {
        let acl = self.context.acl();
        let local = self.context.local_dns();
        let remote = &self.remote_upstream;

        // Start querying name servers
        debug!("DNS lookup {:?} {}", query.query_type(), query.name());

        let remote_response_fut = try_timeout(remote.lookup(&self.context, query), Some(Duration::from_secs(5)));
        let local_response_fut = try_timeout(local.lookup(&self.context, query), Some(Duration::from_secs(5)));

        match should_forward_by_query(acl, query) {
            Some(true) => {
                let remote_response = remote_response_fut.await;
                trace!("pick remote response (query): {:?}", remote_response);
                return (remote_response, true);
            }
            Some(false) => {
                let local_response = local_response_fut.await;
                trace!("pick local response (query): {:?}", local_response);
                return (local_response, false);
            }
            None => (),
        }

        let decider = async {
            let local_response = local_response_fut.await;
            if should_forward_by_response(acl, &local_response, query) {
                None
            } else {
                Some(local_response)
            }
        };
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

    async fn resolve(&self, request: Message) -> Message {
        let mut message = Message::new();
        message.set_id(request.id());
        message.set_recursion_desired(true);
        message.set_recursion_available(true);
        message.set_message_type(MessageType::Response);
        if !request.recursion_desired() {
            message.set_recursion_desired(false);
            message.set_response_code(ResponseCode::NotImp);
        } else if request.op_code() != OpCode::Query || request.message_type() != MessageType::Query {
            message.set_response_code(ResponseCode::NotImp);
        } else if request.query_count() > 0 {
            let (r, forward) = self.acl_lookup(&request.queries()[0]).await;
            if let Ok(result) = r {
                for rec in result.answers() {
                    trace!("dns answer: {:?}", rec);
                    match rec.rdata() {
                        RData::A(ref ip) => {
                            self.context
                                .add_to_reverse_lookup_cache(&IpAddr::V4(*ip), forward)
                                .await
                        }
                        RData::AAAA(ref ip) => {
                            self.context
                                .add_to_reverse_lookup_cache(&IpAddr::V6(*ip), forward)
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
        message
    }
}

async fn run_tcp<Remote>(relay: Arc<DnsRelay<Remote>>, bind_addr: SocketAddr) -> io::Result<()>
where
    Remote: Upstream + Display + Send + Sync + 'static,
{
    let listener = TcpListener::bind(&bind_addr).await?;

    let actual_local_addr = listener.local_addr()?;
    info!(
        "shadowsocks DNS relay (TCP) listening on {}, local {}, remote {}",
        actual_local_addr,
        relay.context.local_dns(),
        relay.remote_upstream
    );

    loop {
        let (mut stream, src) = match listener.accept().await {
            Ok(s) => s,
            Err(err) => {
                error!("accept failed with error: {}", err);
                time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };

        let relay = relay.clone();
        tokio::spawn(async move {
            match upstream::read_message(&mut stream).await {
                Ok(request) => {
                    trace!("received src: {}, query: {:?}", src, request);
                    let message = relay.resolve(request).await;
                    trace!("DNS src: {}, final response: {:?}", src, message);
                    if let Err(err) = upstream::write_message(&mut stream, &message).await {
                        error!("failed to write DNS response, error: {}", err);
                    }
                }
                Err(e) => error!("failed to parse TCP query message from {}, error: {:?}", src, e),
            }
        });
    }
}

async fn run_udp<Remote>(relay: Arc<DnsRelay<Remote>>, bind_addr: SocketAddr) -> io::Result<()>
where
    Remote: Upstream + Display + Send + Sync + 'static,
{
    let socket = create_udp_socket(&bind_addr).await?;

    let actual_local_addr = socket.local_addr()?;
    info!(
        "shadowsocks DNS relay (UDP) listening on {}, local {}, remote {}",
        actual_local_addr,
        relay.context.local_dns(),
        relay.remote_upstream
    );

    let rx = Arc::new(socket);
    let tx = rx.clone();

    loop {
        let mut req_buffer = [0u8; 512];
        let (n, src) = match rx.recv_from(&mut req_buffer).await {
            Ok(x) => x,
            Err(e) => {
                error!("DNS relay read from UDP socket error: {}", e);
                time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };

        trace!("DNS recv {} bytes from {}", n, src);

        let relay = relay.clone();
        let tx = tx.clone();

        tokio::spawn(async move {
            let req_buffer = &req_buffer[..n];

            let request = match Message::from_vec(&req_buffer) {
                Ok(x) => x,
                Err(e) => {
                    error!("failed to parse UDP query message, error: {:?}", e);
                    return;
                }
            };

            trace!("DNS query from {}, {:?}", src, request);
            let message = relay.resolve(request).await;
            trace!("DNS response to {}, {:?}", src, message);

            match message.to_vec() {
                Err(err) => {
                    error!("failed to serialize message, error: {}", err);
                }
                Ok(res_buffer) => {
                    if let Err(err) = tx.send_to(&res_buffer, &src).await {
                        error!("DNS send back UDP error: {}", err);
                    }
                }
            }
        });
    }
}

/// Start a DNS relay local server
pub async fn run(context: SharedContext) -> io::Result<()> {
    let bind_addr = match context.config().dns_bind_addr {
        None => {
            if matches!(context.config().config_type, ConfigType::DnsLocal) {
                match context.config().local_addr {
                    None => panic!("DNS relay requires dns_bind_addr or local_addr"),
                    Some(ref addr) => addr.bind_addr(&context).await?,
                }
            } else {
                panic!("Local dns relay requires dns_bind_addr");
            }
        }
        Some(ref bind_addr) => bind_addr.bind_addr(&context).await?,
    };

    let remote_dns_addr = context
        .config()
        .remote_dns_addr
        .clone()
        .expect("remote query DNS address");

    let proxy_upstream = ProxyUpstream::new(context.clone(), remote_dns_addr).await;
    let proxy_relay = Arc::new(DnsRelay::new(context.clone(), proxy_upstream));

    let udp_dns = run_udp(proxy_relay.clone(), bind_addr);
    let tcp_dns = run_tcp(proxy_relay, bind_addr);

    select! {
        res = udp_dns => res,
        res = tcp_dns => res,
    }
}
