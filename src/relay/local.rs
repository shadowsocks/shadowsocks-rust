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
use config::Config;

/// Relay server running under local environment.
///
/// UDP Associate and Bind commands are not supported currently.
///
/// ```no_run
/// use std::net::{SocketAddr, SocketAddrV4};
///
/// use shadowsocks::relay::Relay;
/// use shadowsocks::relay::RelayLocal;
/// use shadowsocks::config::{Config, ServerConfig};
/// use shadowsocks::crypto::cipher::CipherType;
///
/// let mut config = Config::new();
/// config.local = Some(SocketAddr::V4(SocketAddrV4::new("127.0.0.1".parse().unwrap(), 1080)));
/// config.server = vec![ServerConfig {
///     addr: "127.0.0.1".to_string(),
///     port: 8388,
///     password: "server-password".to_string(),
///     method: CipherType::Aes256Cfb,
///     timeout: None,
///     dns_cache_capacity: 1024,
/// }];
/// RelayLocal::new(config).run();
/// ```
#[derive(Clone)]
pub struct RelayLocal {
    config: Arc<Config>,
}

impl RelayLocal {
    pub fn new(config: Arc<Config>) -> RelayLocal {
        RelayLocal { config: config }
    }

    pub fn run(self) -> io::Result<()> {
        let mut lp = try!(Core::new());
        let handle = lp.handle();
        let tcp_fut = TcpRelayLocal::new(self.config.clone()).run(handle.clone());
        lp.run(tcp_fut)
    }
}
