// The MIT License (MIT)

// Copyright (c) 2014 Y. T. CHUNG <zonyitoo@gmail.com>

// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

//! Local side

use std::sync::Arc;
use std::io;

use tokio_core::reactor::Core;

use relay::tcprelay::local::TcpRelayLocal;
#[cfg(feature = "enable-udp")]
use relay::udprelay::local::UdpRelayLocal;
use relay::dns_resolver::DnsResolver;
use config::Config;

/// Relay server running under local environment.
///
/// ```no_run
/// use std::net::SocketAddr;
/// use std::sync::Arc;
///
/// use shadowsocks::relay::RelayLocal;
/// use shadowsocks::config::{Config, ServerConfig, ServerAddr};
/// use shadowsocks::crypto::CipherType;
///
/// let mut config = Config::new();
/// config.local = Some("127.0.0.1:1080".parse().unwrap());
/// config.server = vec![ServerConfig {
///     addr: ServerAddr::SocketAddr("127.0.0.1:8388".parse().unwrap()),
///     password: "server-password".to_string(),
///     method: CipherType::Aes256Cfb,
///     timeout: None,
/// }];
/// RelayLocal::run(config);
/// ```
#[derive(Clone)]
pub struct RelayLocal;

impl RelayLocal {
    pub fn run(config: Config) -> io::Result<()> {
        let mut lp = try!(Core::new());
        let handle = lp.handle();
        let config = Arc::new(config);
        let dns_resolver = DnsResolver::new(config.dns_cache_capacity);
        let tcp_fut = TcpRelayLocal::run(config, handle, dns_resolver);
        lp.run(tcp_fut)
    }
}
