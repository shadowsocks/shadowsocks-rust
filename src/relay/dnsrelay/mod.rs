use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

use byteorder::{BigEndian, ByteOrder};
use log::debug;
use rand::Rng;

use trust_dns_proto::{
    op::{header::MessageType, response_code::ResponseCode, Message, Query},
    rr::{Name, RData, RecordType},
};

use crate::{
    context::SharedContext,
    relay::{
        socks5::{
            Address,
            Command,
            HandshakeRequest,
            HandshakeResponse,
            Reply,
            TcpRequestHeader,
            TcpResponseHeader,
            SOCKS5_AUTH_METHOD_NONE,
        },
        utils::try_timeout,
    },
};

async fn udp_lookup(qname: &Name, qtype: RecordType, server: SocketAddr) -> io::Result<Message> {
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

    Ok(Message::from_vec(&mut res_buffer)?)
}

async fn socks5_lookup(qname: &Name, qtype: RecordType, socks5: SocketAddr, ns: SocketAddr) -> io::Result<Message> {
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

    let id = rand::thread_rng().gen();
    message.set_id(id);
    message.set_recursion_desired(true);
    message.add_query(query);

    let req_buffer = message.to_vec()?;
    let size = req_buffer.len();
    let mut send_buffer = vec![];

    BigEndian::write_u16(&mut send_buffer[0..2], size as u16);
    send_buffer[2..size + 2].copy_from_slice(&req_buffer[0..size]);
    stream.write_all(&send_buffer[0..size + 2]).await?;

    let mut res_buffer = vec![];
    stream.read_exact(&mut res_buffer[0..2]).await?;

    let size = BigEndian::read_u16(&res_buffer[0..2]) as usize;
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
) -> io::Result<Message> {
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

/// Start a DNS relay local server
pub async fn run(context: SharedContext) -> io::Result<()> {
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
        message.set_message_type(MessageType::Response);

        if request.queries().is_empty() {
            message.set_response_code(ResponseCode::FormErr);
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
