use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
};

use byteorder::{BigEndian, ByteOrder};
use futures::future;
use log::{debug, error, info, trace};
use rand::Rng;

use trust_dns_proto::{
    op::{header::MessageType, response_code::ResponseCode, Message, Query},
    rr::{Name, RData, RecordType},
};

use crate::{
    config::ConfigType,
    context::{Context, SharedContext},
    relay::{socks5::Address, tcprelay::client::Socks5Client, utils::try_timeout},
};

async fn udp_lookup(qname: &Name, qtype: RecordType, server: &SocketAddr) -> io::Result<Message> {
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

async fn socks5_lookup(qname: &Name, qtype: RecordType, socks5: &SocketAddr, ns: &Address) -> io::Result<Message> {
    let mut stream = Socks5Client::connect(ns, &socks5).await?;

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

async fn acl_lookup(
    context: &Context,
    local: &SocketAddr,
    socks5: &SocketAddr,
    qname: &Name,
    qtype: RecordType,
) -> io::Result<Message> {
    let remote = context.config().remote_dns_addr.as_ref().expect("remote dns addr");

    // Start querying name servers
    debug!(
        "attempting lookup of {:?} {} with ns {} and {:?}",
        qtype, qname, local, remote
    );

    let timeout = Some(Duration::new(3, 0));
    let local_response_fut = try_timeout(udp_lookup(qname, qtype, local), timeout);

    let timeout = Some(Duration::new(3, 0));
    let remote_response_fut = try_timeout(socks5_lookup(qname, qtype, socks5, remote), timeout);

    let (local_response, remote_response) = future::join(local_response_fut, remote_response_fut).await;
    let local_response = local_response.unwrap_or_else(|_| Message::new());
    let remote_response = remote_response.unwrap_or_else(|_| Message::new());

    // remove the last dot from fqdn name
    let mut name = qname.to_ascii();
    name.pop();
    let addr = Address::DomainNameAddress(name, 0);
    let qname_in_proxy_list = context.check_qname_in_proxy_list(&addr).await;

    let mut ip_bypassed = false;
    for rec in local_response.answers() {
        let bypassed = match rec.rdata() {
            RData::A(ref ip) => {
                let addr = Address::SocketAddress(SocketAddr::new(IpAddr::from(*ip), 0));
                context.check_target_bypassed(&addr).await
            }
            RData::AAAA(ref ip) => {
                let addr = Address::SocketAddress(SocketAddr::new(IpAddr::from(*ip), 0));
                context.check_target_bypassed(&addr).await
            }
            _ => false,
        };
        if bypassed {
            ip_bypassed = true;
        }
    }

    if local_response.answer_count() == 0 {
        return Ok(remote_response.clone());
    }

    if remote_response.answer_count() == 0 {
        return Ok(local_response.clone());
    }

    if qname_in_proxy_list {
        debug!("pick remote response (qname): {:?}", remote_response);
        Ok(remote_response.clone())
    } else if !ip_bypassed {
        debug!("pick remote response (ip): {:?}", remote_response);
        Ok(remote_response.clone())
    } else {
        debug!("pick DNS local response: {:?}", local_response);
        Ok(local_response.clone())
    }
}

/// Start a DNS relay local server
pub async fn run(shared_context: SharedContext) -> io::Result<()> {
    // Local must be socks5 protocol!
    assert_eq!(shared_context.config().config_type, ConfigType::Socks5Local);

    let local_addr = shared_context.config().local_dns_addr.expect("local dns addr");
    trace!("local DNS server: {}", local_addr);

    let socks5_config = shared_context.config().local.as_ref().expect("socks5 bind addr");
    let socks5_addr = socks5_config.bind_addr(&shared_context).await?;
    trace!("socks5 server: {}", socks5_addr);

    let listen_addr = shared_context.config().dns_relay_addr.expect("dns relay");

    let mut socket = UdpSocket::bind(listen_addr).await?;

    let actual_listen_addr = socket.local_addr()?;
    info!("shadowsocks DNS relay listening on {}", actual_listen_addr);

    loop {
        let mut req_buffer: [u8; 512] = [0; 512];
        let (_, src) = match socket.recv_from(&mut req_buffer).await {
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

        debug!("received query: {:?}", request);

        let context = Arc::clone(&shared_context);

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

                let r = acl_lookup(
                    &context,
                    &local_addr,
                    &socks5_addr,
                    question.name(),
                    question.query_type(),
                )
                .await;

                if let Ok(result) = r {
                    for rec in result.answers() {
                        debug!("dns answer: {:?}", rec);

                        // Remove the last dot in fqdn name
                        let mut name = question.name().to_ascii();
                        name.pop();

                        match rec.rdata() {
                            RData::A(ref ip) => context.add_to_reverse_lookup_cache(IpAddr::from(*ip), name),
                            RData::AAAA(ref ip) => context.add_to_reverse_lookup_cache(IpAddr::from(*ip), name),
                            _ => (),
                        };
                    }

                    message = result;
                    message.set_id(request.id());
                } else {
                    message.set_response_code(ResponseCode::ServFail);
                }
            }

            debug!("dns final response: {:?}", message);

            let res_buffer = message.to_vec().expect("parse message");
            let mut socket = UdpSocket::bind(("0.0.0.0", 0)).await.expect("bind socket");

            match socket.send_to(&res_buffer, src).await {
                Ok(_) => {}
                Err(e) => {
                    error!("failed to send DNS response, error: {:?}", e);
                }
            }
        });
    }
}
