//! HTTP Client

use hyper::{client::ResponseFuture, Body, Client, Request};

use super::connector::Connector;

pub type ProxyHttpClient = Client<Connector, Body>;
pub type BypassHttpClient = Client<Connector, Body>;

pub enum HttpClientEnum {
    Proxy(ProxyHttpClient),
    Bypass(BypassHttpClient),
}

impl HttpClientEnum {
    pub fn send(&self, req: Request<Body>) -> ResponseFuture {
        match self {
            HttpClientEnum::Proxy(c) => c.request(req),
            HttpClientEnum::Bypass(b) => b.request(req),
        }
    }
}
