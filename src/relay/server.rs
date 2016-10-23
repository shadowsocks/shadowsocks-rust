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

use std::sync::Arc;
use std::io;

use tokio_core::reactor::Core;

// #[cfg(feature = "enable-udp")]
// use relay::udprelay::server::UdpRelayServer;
use relay::tcprelay::server::TcpRelayServer;
use config::Config;

/// Relay server running on server side.
///
/// ```no_run
/// use std::net::SocketAddr;
/// use std::sync::Arc;
///
/// use shadowsocks::relay::RelayServer;
/// use shadowsocks::config::{Config, ServerConfig};
/// use shadowsocks::crypto::CipherType;
///
/// let mut config = Config::new();
/// config.server = vec![Arc::new(ServerConfig {
///     addr: "127.0.0.1:8388".parse().unwrap(),
///     password: "server-password".to_string(),
///     method: CipherType::Aes256Cfb,
///     timeout: None,
///     dns_cache_capacity: 1024,
/// })];
/// RelayServer::new(Arc::new(config)).run(1);
/// ```
///
#[derive(Clone)]
pub struct RelayServer {
    config: Arc<Config>,
}

impl RelayServer {
    pub fn new(config: Arc<Config>) -> RelayServer {
        RelayServer { config: config }
    }

    pub fn run(self, threads: usize) -> io::Result<()> {
        let mut lp = try!(Core::new());
        let handle = lp.handle();
        let tcp_fut = TcpRelayServer::new(self.config.clone(), threads).run(handle.clone());
        lp.run(tcp_fut)
    }
}
