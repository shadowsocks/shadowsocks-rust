use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use tokio::sync::mpsc;

#[cfg(not(target_os = "android"))]
use std::net::{Ipv4Addr, SocketAddrV4};
#[cfg(not(target_os = "android"))]
use tokio::net::UdpSocket;

use log::{debug, error, info, warn};
use trust_dns_proto::{
    op::{header::MessageType, response_code::ResponseCode, Message, Query},
    rr::RData,
};

use crate::{
    config::ConfigType,
    context::SharedContext,
    relay::{
        loadbalancing::server::{PlainPingBalancer, ServerType},
        sys::create_udp_socket,
        utils::try_timeout,
    },
};

mod upstream;

async fn acl_lookup<Local, Remote>(
    context: SharedContext,
    local: Arc<Local>,
    remote: Arc<Remote>,
    query: &Query
) -> io::Result<(Message, bool)>
    where
        Local: upstream::Upstream,
        Remote: upstream::Upstream,
{
    // Start querying name servers
    debug!(
        "attempting lookup of {:?} {} with ns {:?} and {:?}",
        query.query_type(), query.name(), local, remote
    );

    let qname_in_proxy_list = context.check_query_in_proxy_list(query);
    let remote_response_fut = try_timeout(remote.lookup(query), Some(Duration::new(3, 0)));
    let local_response_fut = try_timeout(local.lookup(query), Some(Duration::new(3, 0)));

    match qname_in_proxy_list {
        Some(true) => {
            let remote_response = remote_response_fut.await.unwrap_or_else(|_| Message::new());
            debug!("pick remote response (qname): {:?}", remote_response);
            return Ok((remote_response, true));
        }
        Some(false) => {
            let local_response = local_response_fut.await.unwrap_or_else(|_| Message::new());
            debug!("pick local response (qname): {:?}", local_response);
            return Ok((local_response, false));
        }
        None => (),
    }

    let local_response = local_response_fut.await.unwrap_or_else(|_| Message::new());
    for rec in local_response.answers() {
        if rec.record_type() != query.query_type() {
            warn!("local DNS response has inconsistent answer type {} for query {}", rec.record_type(), query);
            break
        }
        let forward = match rec.rdata() {
            RData::A(ref ip) => context.check_ip_in_proxy_list(&IpAddr::from(*ip)),
            RData::AAAA(ref ip) => context.check_ip_in_proxy_list(&IpAddr::from(*ip)),
            RData::PTR(_) => panic!("PTR records should not reach here"),
            _ => context.is_default_in_proxy_list(),
        };
        if !forward {
            debug!("pick local response (response): {:?}", local_response);
            return Ok((local_response, false));
        }
    }

    let remote_response = remote_response_fut.await.unwrap_or_else(|_| Message::new());
    debug!("pick remote response (response): {:?}", remote_response);
    Ok((remote_response, true))
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

            if request.queries().is_empty() {
                message.set_response_code(ResponseCode::FormErr);
            } else {
                let question = &request.queries()[0];
                let r = acl_lookup(context.clone(), local_upstream, remote_upstream, question).await;

                if let Ok((result, forward)) = r {
                    for rec in result.answers() {
                        debug!("dns answer: {:?}", rec);

                        match rec.rdata() {
                            RData::A(ref ip) => context.add_to_reverse_lookup_cache(&IpAddr::from(*ip), forward),
                            RData::AAAA(ref ip) => context.add_to_reverse_lookup_cache(&IpAddr::from(*ip), forward),
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
