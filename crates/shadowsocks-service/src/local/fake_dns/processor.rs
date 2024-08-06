//! DNS request processor

use std::io;

use hickory_resolver::proto::{
    op::{header::MessageType, response_code::ResponseCode, Header, Message, OpCode},
    rr::{
        rdata::{A, AAAA},
        DNSClass, RData, Record, RecordType,
    },
};
use log::{debug, trace};

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
                let record = Record::<RData>::with(query.name().clone(), query.query_type(), 0);
                rsp_message.add_answer(record);
                continue;
            }

            match query.query_type() {
                RecordType::A => {
                    let (ip_addr, expire_duration) = manager.map_domain_ipv4(query.name()).await?;
                    let [a, b, c, d] = ip_addr.octets();

                    let mut record =
                        Record::<RData>::with(query.name().clone(), RecordType::A, expire_duration.as_secs() as u32);
                    record.set_dns_class(query.query_class());
                    record.set_data(Some(RData::A(A::new(a, b, c, d))));
                    rsp_message.add_answer(record);
                }
                RecordType::AAAA => {
                    let (ip_addr, expire_duration) = manager.map_domain_ipv6(query.name()).await?;
                    let [a, b, c, d, e, f, g, h] = ip_addr.segments();

                    let mut record =
                        Record::<RData>::with(query.name().clone(), RecordType::AAAA, expire_duration.as_secs() as u32);
                    record.set_dns_class(query.query_class());
                    record.set_data(Some(RData::AAAA(AAAA::new(a, b, c, d, e, f, g, h))));
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
