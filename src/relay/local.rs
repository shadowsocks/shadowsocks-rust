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

//! Local side

use relay::Relay;
use relay::tcprelay::local::TcpRelayLocal;
// use relay::udprelay::local::UdpRelayLocal;
use config::Config;

/// Relay server running under local environment.
///
/// UDP Associate and Bind commands are not supported currently.
///
/// ```no_run
/// use shadowsocks::relay::Relay;
/// use shadowsocks::relay::RelayLocal;
/// use shadowsocks::config::{Config, ClientConfig, SingleServer, ServerConfig};
///
/// let mut config = Config::new();
/// config.local = Some(ClientConfig {
///     ip: from_str("127.0.0.1").unwrap(),
///     port: 1080
/// });
/// config.server = Some(SingleServer(ServerConfig {
///     address: "127.0.0.1".to_string(),
///     port: 8388,
///     password: "server-password".to_string(),
///     method: "aes-256-cfb".to_string(),
///     timeout: None,
/// }));
/// RelayLocal::new(config).run();
/// ```
#[deriving(Clone)]
pub struct RelayLocal {
    tcprelay: TcpRelayLocal,
    // udprelay: UdpRelayLocal,
}

impl RelayLocal {
    pub fn new(config: Config) -> RelayLocal {
        let tcprelay = TcpRelayLocal::new(config.clone());
        // let udprelay = UdpRelayLocal::new(config.clone());
        RelayLocal {
            tcprelay: tcprelay,
            // udprelay: udprelay,
        }
    }
}

impl Relay for RelayLocal {
    fn run(&self) {
        let tcprelay = self.tcprelay.clone();
        spawn(proc() tcprelay.run());

        // let udprelay = self.udprelay.clone();
        // spawn(proc() udprelay.run());
    }
}
