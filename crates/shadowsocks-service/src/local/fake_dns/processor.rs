//! DNS request processor

use std::io;

use hickory_resolver::proto::{
    op::{Header, Message, OpCode, header::MessageType, response_code::ResponseCode},
    rr::{
        DNSClass, RData, Record, RecordType,
        rdata::{A, AAAA},
    },
};
use log::{debug, trace, warn};

use super::manager::FakeDnsManager;

pub async fn handle_dns_request(req_message: &Message, manager: &FakeDnsManager) -> io::Result<Message> {
    let mut rsp_message = Message::new();
    let rsp_header = Header::response_from_request(req_message.header());
    rsp_message.set_header(rsp_header);

    if req_message.op_code() != OpCode::Query || req_message.message_type() != MessageType::Query {
        rsp_message.set_response_code(ResponseCode::NotImp);
    } else {
        for query in req_message.queries() {
            // Copy all the queries into response.
            rsp_message.add_query(query.clone());

            if query.query_class() != DNSClass::IN {
                // let record = Record::<RData>::from_rdata(query.name().clone(), 0, query.query_type());
                // rsp_message.add_answer(record);
                warn!(
                    "Query class: {:?} is not supported. Full {:?}",
                    query.query_class(),
                    req_message
                );
                continue;
            }

            match query.query_type() {
                RecordType::A => {
                    let (ip_addr, expire_duration) = manager.map_domain_ipv4(query.name()).await?;

                    let mut record = Record::<RData>::from_rdata(
                        query.name().clone(),
                        expire_duration.as_secs() as u32,
                        RData::A(A(ip_addr)),
                    );
                    record.set_dns_class(query.query_class());
                    rsp_message.add_answer(record);
                }
                RecordType::AAAA => {
                    let (ip_addr, expire_duration) = manager.map_domain_ipv6(query.name()).await?;

                    let mut record = Record::<RData>::from_rdata(
                        query.name().clone(),
                        expire_duration.as_secs() as u32,
                        RData::AAAA(AAAA(ip_addr)),
                    );
                    record.set_dns_class(query.query_class());
                    rsp_message.add_answer(record);
                }
                _ => {
                    debug!("fakedns {} not supported. {:?}", query.query_type(), query);
                }
            }
        }
    }

    trace!("QUERY {:?} ANSWER {:?}", req_message, rsp_message);

    Ok(rsp_message)
}
