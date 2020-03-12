use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use tokio::{
    io::Result,
    net::{TcpStream, UdpSocket},
    prelude::*,
    time,
};

use log::debug;

use trust_dns_proto::{op::*, rr::*};

use crate::{context::SharedContext, relay::socks5::*};

pub async fn try_timeout<T, F>(fut: F, timeout: Option<Duration>) -> io::Result<T>
where
    F: Future<Output = Result<T>>,
{
    match timeout {
        Some(t) => time::timeout(t, fut).await?,
        None => fut.await,
    }
    .map_err(From::from)
}

async fn udp_lookup(qname: &Name, qtype: RecordType, server: SocketAddr) -> Result<Message> {
    let mut socket = UdpSocket::bind(("0.0.0.0", 0)).await?;

    let mut message = Message::new();
    let mut query = Query::new();

    query.set_query_type(qtype);
    query.set_name(qname.clone());

    message.set_id(6666);
    message.set_recursion_desired(true);
    message.add_query(query);

    let req_buffer = message.to_vec()?;
    socket.send_to(&req_buffer, server).await?;

    let mut res_buffer = vec![0; 512];
    socket.recv_from(&mut res_buffer).await?;

    Ok(Message::from_vec(&mut res_buffer)?)
}

async fn socks5_lookup(qname: &Name, qtype: RecordType, socks5: SocketAddr, ns: SocketAddr) -> Result<Message> {
    let mut stream = TcpStream::connect(socks5).await?;

    // 1. Handshake
    let hs = HandshakeRequest::new(vec![SOCKS5_AUTH_METHOD_NONE]);
    hs.write_to(&mut stream).await?;
    stream.flush().await?;

    let hsp = HandshakeResponse::read_from(&mut stream).await?;
    assert_eq!(hsp.chosen_method, SOCKS5_AUTH_METHOD_NONE);

    // 2. Send request header
    let addr = Address::SocketAddress(ns);
    let h = TcpRequestHeader::new(Command::TcpConnect, addr);
    h.write_to(&mut stream).await?;
    stream.flush().await?;

    let hp = TcpResponseHeader::read_from(&mut stream).await?;
    match hp.reply {
        Reply::Succeeded => (),
        r => {
            let err = io::Error::new(io::ErrorKind::Other, format!("{}", r));
            return Err(err);
        }
    }

    let mut message = Message::new();
    let mut query = Query::new();

    query.set_query_type(qtype);
    query.set_name(qname.clone());

    message.set_id(6666);
    message.set_recursion_desired(true);
    message.add_query(query);

    let req_buffer = message.to_vec()?;
    let size = req_buffer.len();
    let mut size_buffer: [u8; 2] = [((size >> 8) & 0xFF) as u8, ((size >> 0) & 0xFF) as u8];
    let mut send_buffer: [u8; 512 + 2] = [0; 512 + 2];
    send_buffer[..2].copy_from_slice(&size_buffer[..2]);
    send_buffer[2..size + 2].copy_from_slice(&req_buffer[0..size]);
    stream.write_all(&send_buffer[0..size + 2]).await?;

    stream.read_exact(&mut size_buffer[0..2]).await?;

    let mut res_buffer = vec![0; 512];
    let size = ((size_buffer[0] as usize) << 8) + (size_buffer[1] as usize);
    stream.read_exact(&mut res_buffer[0..size]).await?;

    Ok(Message::from_vec(&mut res_buffer)?)
}

async fn acl_lookup(
    context: &SharedContext,
    local: SocketAddr,
    remote: SocketAddr,
    socks5: SocketAddr,
    qname: &Name,
    qtype: RecordType,
) -> Result<Message> {
    // Start querying name servers
    debug!(
        "attempting lookup of {:?} {} with ns {} and {}",
        qtype, qname, local, remote
    );

    let timeout = Some(Duration::new(5, 0));

    let local_response = try_timeout(udp_lookup(qname, qtype.clone(), local), timeout)
        .await
        .unwrap_or(Message::new());
    let remote_response = try_timeout(socks5_lookup(qname, qtype.clone(), socks5, remote), timeout)
        .await
        .unwrap_or(Message::new());

    let addr = Address::DomainNameAddress(qname.to_string(), 0);
    let qname_bypassed = context.check_target_bypassed(&addr).await;

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

    if qname_bypassed {
        debug!("Pick local response");
        Ok(local_response.clone())
    } else if ip_bypassed {
        debug!("Pick local response");
        Ok(local_response.clone())
    } else {
        debug!("Pick remote response");
        Ok(remote_response.clone())
    }
}

pub async fn run(context: SharedContext) -> Result<()> {
    let local_addr = context.config().local_dns_addr.expect("local dns");
    debug!("Local DNS server: {}", local_addr);

    let remote_addr = context.config().remote_dns_addr.expect("remote dns");
    debug!("Remote DNS server: {}", remote_addr);

    let socks5_config = context.config().local.as_ref().expect("socks5");
    let socks5_addr = socks5_config.bind_addr(&*context).await?;
    debug!("SOCKS5 server: {}", socks5_addr);

    let listen_addr = context.config().dns_relay_addr.expect("dns relay");
    debug!("Listen on {}", listen_addr);

    let mut socket = UdpSocket::bind(listen_addr).await?;

    loop {
        let mut req_buffer: [u8; 512] = [0; 512];
        let (_, src) = match socket.recv_from(&mut req_buffer).await {
            Ok(x) => x,
            Err(e) => {
                debug!("Failed to read from UDP socket: {:?}", e);
                continue;
            }
        };

        let request = match Message::from_vec(&mut req_buffer) {
            Ok(x) => x,
            Err(e) => {
                debug!("Failed to parse UDP query message: {:?}", e);
                continue;
            }
        };

        let mut message = Message::new();
        message.set_id(request.id());
        message.set_recursion_desired(true);
        message.set_recursion_available(true);
        message.set_message_type(header::MessageType::Response);

        if request.queries().is_empty() {
            message.set_response_code(response_code::ResponseCode::FormErr);
        } else {
            let question = &request.queries()[0];
            debug!("Received query: {:?}", question);

            if let Ok(result) = acl_lookup(
                &context,
                local_addr,
                remote_addr,
                socks5_addr,
                question.name(),
                question.query_type(),
            )
            .await
            {
                message.add_query(question.clone());
                message.set_response_code(result.response_code());

                for rec in result.answers() {
                    debug!("Answer: {:?}", rec);
                    match rec.rdata() {
                        RData::A(ref ip) => {
                            context.add_to_reverse_lookup_cache(IpAddr::from(*ip), question.name().to_ascii())
                        }
                        RData::AAAA(ref ip) => {
                            context.add_to_reverse_lookup_cache(IpAddr::from(*ip), question.name().to_ascii())
                        }
                        _ => (),
                    };
                    message.add_answer(rec.clone());
                }
                for rec in result.additionals() {
                    debug!("Additionals: {:?}", rec);
                    message.add_additional(rec.clone());
                }
            } else {
                message.set_response_code(ResponseCode::ServFail);
            }
        }

        let res_buffer = message.to_vec()?;
        match socket.send_to(&res_buffer, src).await {
            Ok(_) => {}
            Err(e) => {
                debug!("Failed to send response: {:?}", e);
                continue;
            }
        };
    }
}
