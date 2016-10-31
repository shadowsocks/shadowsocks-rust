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

//! Server side

use std::rc::Rc;
use std::io;

use tokio_core::reactor::Core;

use futures::{self, Future};

use relay::udprelay::server::UdpRelayServer;
use relay::tcprelay::server::TcpRelayServer;
use relay::dns_resolver::DnsResolver;
use relay::boxed_future;
use config::Config;

/// Relay server running on server side.
///
/// ```no_run
/// use shadowsocks::relay::RelayServer;
/// use shadowsocks::config::{Config, ServerConfig, ServerAddr};
/// use shadowsocks::crypto::CipherType;
///
/// let mut config = Config::new();
/// config.server = vec![
///     ServerConfig::basic("127.0.0.1:8388".parse().unwrap(),
///                         "server-password".to_string(),
///                         CipherType::Aes256Cfb)];
/// RelayServer::run(config).unwrap();
/// ```
///
#[derive(Clone)]
pub struct RelayServer;

impl RelayServer {
    pub fn run(config: Config) -> io::Result<()> {
        let mut lp = try!(Core::new());

        let handle = lp.handle();
        let config = Rc::new(config);

        let dns_resolver = DnsResolver::new(config.dns_cache_capacity);

        let tcp_fut = TcpRelayServer::run(config.clone(), handle.clone(), dns_resolver.clone());

        let udp_fut = if config.enable_udp {
            UdpRelayServer::run(config, handle, dns_resolver)
        } else {
            boxed_future(futures::finished(()))
        };

        lp.run(tcp_fut.join(udp_fut).map(|_| ()))
    }
}
