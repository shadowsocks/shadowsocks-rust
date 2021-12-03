//! HTTP Client

use hyper::{client::ResponseFuture, Body, Client, Request};

use super::connector::{BypassConnector, ProxyConnector};

pub type ProxyHttpClient = Client<ProxyConnector, Body>;
pub type BypassHttpClient = Client<BypassConnector, Body>;

pub enum HttpClientEnum {
    Proxy(ProxyHttpClient),
    Bypass(BypassHttpClient),
}

impl HttpClientEnum {
    pub fn send(&self, req: Request<Body>) -> ResponseFuture {
        return match self {
            HttpClientEnum::Proxy(c) => c.request(req),
            HttpClientEnum::Bypass(b) => b.request(req),
        };
    }
}
