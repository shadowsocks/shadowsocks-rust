//! DNS request processor

use std::io;

use hickory_resolver::proto::{
    op::{Message, MessageType, OpCode, ResponseCode, UpdateMessage},
    rr::{
        DNSClass, RData, Record, RecordType,
        rdata::{A, AAAA},
    },
};
use log::{debug, trace, warn};

use super::manager::FakeDnsManager;

pub async fn handle_dns_request(req_message: &Message, manager: &FakeDnsManager) -> io::Result<Message> {
    let mut rsp_message = Message::response(req_message.id(), req_message.op_code);

    if req_message.op_code != OpCode::Query || req_message.message_type != MessageType::Query {
        rsp_message.metadata.response_code = ResponseCode::NotImp;
    } else {
        for query in req_message.queries.iter() {
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
                    record.dns_class = query.query_class();
                    rsp_message.add_answer(record);
                }
                RecordType::AAAA => {
                    let (ip_addr, expire_duration) = manager.map_domain_ipv6(query.name()).await?;

                    let mut record = Record::<RData>::from_rdata(
                        query.name().clone(),
                        expire_duration.as_secs() as u32,
                        RData::AAAA(AAAA(ip_addr)),
                    );
                    record.dns_class = query.query_class();
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
