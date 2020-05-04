use std::{
    io,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};

#[cfg(target_os = "android")]
use std::path::PathBuf;
#[cfg(target_os = "android")]
use tokio::net::UnixStream;

#[cfg(not(target_os = "android"))]
use std::net::{Ipv4Addr, SocketAddrV4};
#[cfg(not(target_os = "android"))]
use tokio::net::UdpSocket;

use byteorder::{BigEndian, ByteOrder};
use log::{debug, error, info};
use rand::Rng;
use trust_dns_proto::{
    op::{header::MessageType, response_code::ResponseCode, Message, Query},
    rr::{Name, RData, RecordType},
};

use crate::{
    config::{ConfigType, ServerConfig},
    context::SharedContext,
    relay::{
        loadbalancing::server::{PlainPingBalancer, ServerType},
        socks5::Address,
        sys::create_udp_socket,
        tcprelay::ProxyStream,
        utils::try_timeout,
    },
};

async fn stream_lookup<T>(qname: &Name, qtype: RecordType, stream: &mut T) -> io::Result<Message>
where
    T: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut message = Message::new();
    let mut query = Query::new();

    query.set_query_type(qtype);
    query.set_name(qname.clone());

    let id = rand::thread_rng().gen();
    message.set_id(id);
    message.set_recursion_desired(true);
    message.add_query(query);

    let req_buffer = message.to_vec()?;
    let size = req_buffer.len();
    let mut send_buffer = vec![0; size + 2];

    BigEndian::write_u16(&mut send_buffer[0..2], size as u16);
    send_buffer[2..size + 2].copy_from_slice(&req_buffer[0..size]);
    stream.write_all(&send_buffer[0..size + 2]).await?;

    let mut res_buffer = vec![0; 2];
    stream.read_exact(&mut res_buffer[0..2]).await?;

    let size = BigEndian::read_u16(&res_buffer[0..2]) as usize;
    let mut res_buffer = vec![0; size];
    stream.read_exact(&mut res_buffer[0..size]).await?;

    Ok(Message::from_vec(&res_buffer)?)
}

#[cfg(target_os = "android")]
async fn local_lookup(qname: &Name, qtype: RecordType, path: &PathBuf) -> io::Result<Message> {
    let mut stream = UnixStream::connect(path).await?;
    stream_lookup(qname, qtype, &mut stream).await
}

#[cfg(not(target_os = "android"))]
async fn local_lookup(qname: &Name, qtype: RecordType, server: &SocketAddr) -> io::Result<Message> {
    let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0));
    let mut socket = UdpSocket::bind(bind_addr).await?;

    let mut message = Message::new();
    let mut query = Query::new();

    query.set_query_type(qtype);
    query.set_name(qname.clone());

    let id = rand::thread_rng().gen();
    message.set_id(id);
    message.set_recursion_desired(true);
    message.add_query(query);

    let req_buffer = message.to_vec()?;
    socket.send_to(&req_buffer, server).await?;

    let mut res_buffer = vec![0; 512];
    socket.recv_from(&mut res_buffer).await?;

    Ok(Message::from_vec(&res_buffer)?)
}

async fn proxy_lookup(
    context: SharedContext,
    svr_cfg: &ServerConfig,
    ns: &Address,
    qname: &Name,
    qtype: RecordType,
) -> io::Result<Message> {
    let mut stream = ProxyStream::connect_proxied(context, svr_cfg, ns).await?;
    stream_lookup(qname, qtype, &mut stream).await
}

async fn acl_lookup(
    context: SharedContext,
    svr_cfg: &ServerConfig,
    #[cfg(target_os = "android")] local: &PathBuf,
    #[cfg(not(target_os = "android"))] local: &SocketAddr,
    remote: &Address,
    qname: &Name,
    qtype: RecordType,
) -> io::Result<(Message, bool)> {
    // Start querying name servers
    debug!(
        "attempting lookup of {:?} {} with ns {:?} and {:?}",
        qtype, qname, local, remote
    );

    // remove the last dot from fqdn name
    let mut name = qname.to_ascii();
    name.pop();
    let addr = Address::DomainNameAddress(name, 0);
    let qname_in_proxy_list = context.check_qname_in_proxy_list(&addr);

    let remote_response_fut = async {
        match qname_in_proxy_list {
            Some(false) => None,
            _ => {
                let timeout = Some(Duration::new(3, 0));
                try_timeout(proxy_lookup(context.clone(), svr_cfg, remote, qname, qtype), timeout).await.ok()
            }
        }
    };

    let local_response = match qname_in_proxy_list {
        Some(true) => None,
        _ => {
            let timeout = Some(Duration::new(3, 0));
            try_timeout(local_lookup(qname, qtype, local), timeout).await.ok()
        }
    }.unwrap_or_else(|| Message::new());

    match qname_in_proxy_list {
        Some(true) => {
            let remote_response = remote_response_fut.await.unwrap_or_else(|| Message::new());
            debug!("pick remote response (qname): {:?}", remote_response);
            return Ok((remote_response.clone(), true));
        }
        Some(false) => {
            debug!("pick local response (qname): {:?}", local_response);
            return Ok((local_response.clone(), false));
        }
        None => (),
    }

    if local_response.answer_count() == 0 {
        let remote_response = remote_response_fut.await.unwrap_or_else(|| Message::new());
        return Ok((remote_response.clone(), true));
    }

    for rec in local_response.answers() {
        let forward = match rec.rdata() {
            RData::A(ref ip) => context.check_ip_in_proxy_list(&IpAddr::from(*ip)),
            RData::AAAA(ref ip) => context.check_ip_in_proxy_list(&IpAddr::from(*ip)),
            _ => true,
        };
        if !forward {
            debug!("pick local response (ip): {:?}", local_response);
            return Ok((local_response.clone(), false))
        }
    }

    let remote_response = remote_response_fut.await.unwrap_or_else(|| Message::new());
    debug!("pick remote response (ip): {:?}", remote_response);
    Ok((remote_response.clone(), true))
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

    // FIXME: We use TCP to send remote queries by default, which should be configuable.
    let balancer = PlainPingBalancer::new(context.clone(), ServerType::Tcp).await;

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
        let mut qtx = qtx.clone();
        let server = balancer.pick_server();

        tokio::spawn(async move {
            let mut message = Message::new();
            message.set_id(request.id());
            message.set_recursion_desired(true);
            message.set_recursion_available(true);
            message.set_message_type(MessageType::Response);

            if request.queries().is_empty() {
                message.set_response_code(ResponseCode::FormErr);
            } else {
                let config = context.config();

                #[cfg(target_os = "android")]
                let local_addr = config.local_dns_path.as_ref().expect("local query DNS path");
                #[cfg(not(target_os = "android"))]
                let local_addr = config.local_dns_addr.as_ref().expect("local query DNS address");

                let remote_addr = config.remote_dns_addr.as_ref().expect("remote query DNS address");

                let question = &request.queries()[0];

                let qname = question.name();
                let qtype = question.query_type();
                let svr_cfg = server.server_config();

                let r = acl_lookup(context.clone(), svr_cfg, &local_addr, &remote_addr, qname, qtype).await;

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
