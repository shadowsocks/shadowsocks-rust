use std::{net::SocketAddr, time::Duration};

use clap::{App, Arg};
use shadowsocks::{
    config::{ServerAddr, ServerType},
    context::Context,
    net::{ConnectOpts, UdpSocket},
};
use tokio::time;
use trust_dns_proto::{
    op::{Message, Query},
    rr::{Name, RecordType},
};

#[tokio::main]
async fn main() {
    env_logger::init();

    let matches = App::new("dns-pressure")
        .arg(
            Arg::new("OUTBOUND_BIND_INTERFACE")
                .long("outbound-bind-interface")
                .takes_value(true),
        )
        .arg(
            Arg::new("NAMESERVER_ADDR")
                .long("nameserver-addr")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::new("DNS_QUERY_NAME")
                .long("dns-query-name")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::new("TOTAL_CLIENT_COUNT")
                .long("total-client-count")
                .takes_value(true),
        )
        .get_matches();

    let mut connect_opts = ConnectOpts::default();
    if let Some(outbound_bind_interface) = matches.value_of("OUTBOUND_BIND_INTERFACE") {
        connect_opts.bind_interface = Some(outbound_bind_interface.to_owned());
    }

    let dns_query_name = matches.value_of_t_or_exit::<String>("DNS_QUERY_NAME");
    let nameserver_addr = matches.value_of_t_or_exit::<SocketAddr>("NAMESERVER_ADDR");

    let mut total_client_count = 10;
    if let Ok(c) = matches.value_of_t::<usize>("TOTAL_CLIENT_COUNT") {
        total_client_count = c;
    }

    let name = Name::from_utf8(dns_query_name).expect("name");
    let query = Query::query(name, RecordType::A);

    let mut message = Message::new();
    message.set_recursion_desired(true);
    message.add_query(query);

    let context = Context::new_shared(ServerType::Local);

    let mut tasks = Vec::new();

    for _ in 0..total_client_count {
        let mut message = message.clone();
        let context = context.clone();
        let connect_opts = connect_opts.clone();

        let handle = tokio::spawn(async move {
            loop {
                let server_addr = ServerAddr::from(nameserver_addr);
                let socket = UdpSocket::connect_server_with_opts(&context, &server_addr, &connect_opts)
                    .await
                    .expect("connect");

                message.set_id(rand::random());

                let buffer = message.to_vec().expect("query serialize");
                let n = socket.send(&buffer).await.expect("send");
                if n < buffer.len() {
                    eprintln!("message sent shorter, expected {} bytes, but {} bytes", buffer.len(), n);
                }

                let mut recv_buffer = [0u8; 65535];
                let n = match time::timeout(Duration::from_secs(5), socket.recv(&mut recv_buffer)).await {
                    Ok(Ok(n)) => n,
                    Ok(Err(err)) => {
                        eprintln!("socket recv error: {}", err);
                        continue;
                    }
                    Err(..) => {
                        eprintln!("recv timeout");
                        continue;
                    }
                };

                let recv_message = match Message::from_vec(&recv_buffer[..n]) {
                    Ok(m) => m,
                    Err(err) => {
                        eprintln!("received invalid DNS message, err: {}", err);
                        continue;
                    }
                };

                if recv_message.id() != message.id() {
                    eprintln!(
                        "received unmatched DNS query respond, expected: {}, but: {}",
                        message.id(),
                        recv_message.id()
                    );
                }
            }
        });
        tasks.push(handle);
    }

    for task in tasks {
        let _ = task.await;
    }
}
