// The MIT License (MIT)

// Copyright (c) 2014 Y. T. CHUNG

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

use std::task::try_future;

// use relay::udprelay::server::UdpRelayServer;
use relay::tcprelay::server::TcpRelayServer;
use relay::Relay;
use config::Config;

/// Relay server running on server side.
///
/// UDP Associate and Bind commands are not supported currently.
///
/// ```no_run
/// use std::io::net::ip::SocketAddr;
///
/// use shadowsocks::relay::Relay;
/// use shadowsocks::relay::RelayServer;
/// use shadowsocks::config::{Config, SingleServer, ServerConfig};
///
/// let mut config = Config::new();
/// config.server = Some(SingleServer(ServerConfig {
///     addr: SocketAddr {
///         ip: from_str("127.0.0.1").unwrap(),
///         port: 8388,
///     },
///     password: "server-password".to_string(),
///     method: "aes-256-cfb".to_string(),
///     timeout: None,
///     dns_cache_capacity: 1024,
/// }));
/// RelayServer::new(config).run();
/// ```
///
/// It should be noticed that `config.server` has to be `Some(SingleServer)` here.
#[deriving(Clone)]
pub struct RelayServer {
    tcprelay: TcpRelayServer,
    // udprelay: UdpRelayServer,
}

impl RelayServer {
    pub fn new(config: Config) -> RelayServer {
        let tcprelay = TcpRelayServer::new(config.clone());
        // let udprelay = UdpRelayServer::new(config.clone());
        RelayServer {
            tcprelay: tcprelay,
            // udprelay: udprelay,
        }
    }
}

impl Relay for RelayServer {
    fn run(&self) {
        let tcprelay = self.tcprelay.clone();
        // let udprelay = self.udprelay.clone();

        let tcp_future = try_future(proc() tcprelay.run());
        // spawn(proc() udprelay.run());

        drop(tcp_future.unwrap());
    }
}
