use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use tokio::sync::mpsc;

use log::{debug, error, info, warn};
use trust_dns_proto::{
    op::{header::MessageType, response_code::ResponseCode, Message, Query},
    rr::{DNSClass, Name, RData, RecordType},
};

use crate::{
    acl::AccessControl,
    config::ConfigType,
    context::SharedContext,
    relay::{
        loadbalancing::server::{PlainPingBalancer, ServerType},
        sys::create_udp_socket,
        utils::try_timeout,
    },
};

mod upstream;

fn should_forward_by_ptr_name(acl: &AccessControl, name: &Name) -> bool {
    let mut iter = name.iter().rev();
    let mut next = || std::str::from_utf8(iter.next().unwrap_or(&[48])).unwrap_or("*");
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
                segments[0], segments[1], segments[2], segments[3], segments[4], segments[5], segments[6], segments[7]
            )))
        }
        _ => acl.is_default_in_proxy_list(),
    }
}

/// given the query, determine whether remote/local query should be used, or inconclusive
fn should_forward_by_query(acl: &Option<AccessControl>, query: &Query) -> Option<bool> {
    if let Some(acl) = acl {
        if query.query_class() != DNSClass::IN {
            // unconditionally use default for all non-IN queries
            Some(acl.is_default_in_proxy_list())
        } else if query.query_type() == RecordType::PTR {
            Some(should_forward_by_ptr_name(acl, query.name()))
        } else {
            let result = acl.check_name_in_proxy_list(query.name());
            if result == None && match query.query_type() {
                RecordType::A => acl.is_ipv4_empty(),
                RecordType::AAAA => acl.is_ipv6_empty(),
                RecordType::ANY => acl.is_ipv4_empty() && acl.is_ipv6_empty(),
                RecordType::PTR => unreachable!(),
                _ => true,
            } {
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
    acl: &Option<AccessControl>,
    local_response: &io::Result<Message>,
    query: &Query,
) -> bool {
    if let Some(acl) = acl {
        macro_rules! examine_record {
            ($rec:ident, $is_answer:expr) => {
                if let RData::CNAME(ref name) = $rec.rdata() {
                    match acl.check_name_in_proxy_list(name) {
                        Some(value) => return value,
                        None => continue,
                    }
                } else if $is_answer && !query.query_type().is_any() && $rec.record_type() != query.query_type() {
                    warn!("local DNS response has inconsistent answer type {} for query {}", $rec.record_type(), query);
                    return true;
                }
                let forward = match $rec.rdata() {
                    RData::A(ref ip) => acl.check_ip_in_proxy_list(&IpAddr::V4(*ip)),
                    RData::AAAA(ref ip) => acl.check_ip_in_proxy_list(&IpAddr::V6(*ip)),
                    RData::PTR(_) => unreachable!(),
                    _ => acl.is_default_in_proxy_list(),
                };
                if !forward {
                    return false;
                }
            };
        }
        if let Ok(ref local_response) = local_response {
            for rec in local_response.answers() {
                examine_record!(rec, true);
            }
            for rec in local_response.additionals() {
                examine_record!(rec, false);
            }
        }
        true
    } else {
        unreachable!()
    }
}

async fn acl_lookup<Local, Remote>(
    acl: &Option<AccessControl>,
    local: Arc<Local>,
    remote: Arc<Remote>,
    query: &Query
) -> (io::Result<Message>, bool)
    where
        Local: upstream::Upstream,
        Remote: upstream::Upstream,
{
    // Start querying name servers
    debug!(
        "attempting lookup of {:?} {} with ns {:?} and {:?}",
        query.query_type(), query.name(), local, remote
    );

    let remote_response_fut = try_timeout(remote.lookup(query), Some(Duration::new(3, 0)));
    let local_response_fut = try_timeout(local.lookup(query), Some(Duration::new(3, 0)));

    match should_forward_by_query(acl, query) {
        Some(true) => {
            let remote_response = remote_response_fut.await;
            debug!("pick remote response (query): {:?}", remote_response);
            return (remote_response, true);
        }
        Some(false) => {
            let local_response = local_response_fut.await;
            debug!("pick local response (query): {:?}", local_response);
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
            response = &mut remote_response_fut => {
                if use_remote {
                    debug!("pick remote response (response): {:?}", response);
                    return (response, true);
                } else {
                    remote_response = Some(response);
                }
            }
            decision = &mut decider => {
                if let Some(local_response) = decision {
                    debug!("pick local response (response): {:?}", local_response);
                    return (local_response, false);
                } else if let Some(remote_response) = remote_response {
                    debug!("pick remote response (response): {:?}", remote_response);
                    return (remote_response, true);
                } else {
                    use_remote = true;
                }
            }
        }
    }
}

/// Start a DNS relay local server
pub async fn run(context: SharedContext) -> io::Result<()> {
    let local_addr = match context.config().config_type {
        ConfigType::DnsLocal => {
            // Standalone server
            context.config().local_addr.as_ref().expect("local config")
        }
        c if c.is_local() => {
            // Integrated mode
            context.config().dns_local_addr.as_ref().expect("dns relay addr")
        }
        _ => {
            panic!("ConfigType must be DnsLocal");
        }
    };

    let bind_addr = local_addr.bind_addr(&context).await?;

    let socket = create_udp_socket(&bind_addr).await?;

    let actual_local_addr = socket.local_addr()?;
    info!("shadowsocks DNS relay listening on {}", actual_local_addr);

    let (mut rx, mut tx) = socket.split();
    let (qtx, mut qrx) = mpsc::channel::<(SocketAddr, Vec<u8>)>(1024);

    tokio::spawn(async move {
        while let Some((src, pkt)) = qrx.recv().await {
            if let Err(err) = tx.send_to(&pkt, &src).await {
                error!("failed to send packet {} bytes to {}, error: {}", pkt.len(), src, err);
            }
        }
    });

    let config = context.config();
    #[cfg(target_os = "android")]
        let local_upstream = Arc::new(upstream::UnixSocketUpstream {
        path: config.local_dns_path.clone().expect("local query DNS path"),
    });
    #[cfg(not(target_os = "android"))]
        let local_upstream = Arc::new(upstream::UdpUpstream {
        server: config.local_dns_addr.clone().expect("local query DNS address"),
    });
    // FIXME: We use TCP to send remote queries by default, which should be configuable.
    let balancer = PlainPingBalancer::new(context.clone(), ServerType::Tcp).await;
    let remote_upstream = Arc::new(upstream::ProxyTcpUpstream {
        context: context.clone(),
        svr_cfg: move || balancer.pick_server().server_config().clone(),
        ns: config.remote_dns_addr.clone().expect("remote query DNS address"),
    });

    loop {
        let mut req_buffer: [u8; 512] = [0; 512];
        let (_, src) = match rx.recv_from(&mut req_buffer).await {
            Ok(x) => x,
            Err(e) => {
                error!("DNS relay read from UDP socket error: {}", e);
                continue;
            }
        };

        let request = match Message::from_vec(&req_buffer) {
            Ok(x) => x,
            Err(e) => {
                error!("failed to parse UDP query message, error: {:?}", e);
                continue;
            }
        };

        debug!("received src: {}, query: {:?}", src, request);

        let context = context.clone();
        let local_upstream = Arc::clone(&local_upstream);
        let remote_upstream = Arc::clone(&remote_upstream);
        let mut qtx = qtx.clone();

        tokio::spawn(async move {
            let mut message = Message::new();
            message.set_id(request.id());
            message.set_recursion_desired(true);
            message.set_recursion_available(true);
            message.set_message_type(MessageType::Response);

            if !request.recursion_desired() {
                message.set_recursion_desired(false);
                message.set_response_code(ResponseCode::NotImp);
            } else if request.query_count() > 0 {
                let question = &request.queries()[0];
                let (r, forward) = acl_lookup(context.acl(), local_upstream, remote_upstream, question).await;

                if let Ok(result) = r {
                    for rec in result.answers() {
                        debug!("dns answer: {:?}", rec);

                        match rec.rdata() {
                            RData::A(ref ip) => context.add_to_reverse_lookup_cache(&IpAddr::V4(*ip), forward),
                            RData::AAAA(ref ip) => context.add_to_reverse_lookup_cache(&IpAddr::V6(*ip), forward),
                            _ => (),
                        }
                    }

                    message = result;
                    message.set_id(request.id());
                } else {
                    message.set_response_code(ResponseCode::ServFail);
                }
            }

            debug!("DNS src: {}, final response: {:?}", src, message);

            match message.to_vec() {
                Err(err) => {
                    error!("failed to serialize message, error: {}", err);
                }
                Ok(res_buffer) => {
                    if let Err(..) = qtx.send((src, res_buffer)).await {
                        error!("DNS send back queue is closed unexpectly");
                    }
                }
            }
        });
    }
}
