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

use coio::Builder;

#[cfg(feature = "enable-udp")]
use relay::udprelay::server::UdpRelayServer;
use relay::tcprelay::server::TcpRelayServer;
use relay::{Relay, COROUTINE_STACK_SIZE};
use config::Config;

/// Relay server running on server side.
///
/// UDP Associate and Bind commands Builderarnew().stack_size(COROUTINE_STACK_SIZE).e not supported currently.
///
/// ```no_run
/// use std::net::SocketAddr;
///
/// use shadowsocks::relay::Relay;
/// use shadowsocks::relay::RelayServer;
/// use shadowsocks::config::{Config, ServerConfig};
/// use shadowsocks::crypto::cipher::CipherType;
///
/// let mut config = Config::new();
/// config.server = vec![ServerConfig {
///     addr: "127.0.0.1".to_string(),
///     port: 8388,
///     password: "server-password".to_string(),
///     method: CipherType::Aes256Cfb,
///     timeout: None,
///     dns_cache_capacity: 1024,
/// }];
/// RelayServer::new(config).run(1);
/// ```
///
#[derive(Clone)]
pub struct RelayServer {
    enable_udp: bool,
    tcprelay: TcpRelayServer,
    #[cfg(feature = "enable-udp")]
    udprelay: UdpRelayServer,
}

impl RelayServer {
    #[cfg(feature = "enable-udp")]
    pub fn new(config: Config) -> RelayServer {
        let tcprelay = TcpRelayServer::new(config.clone());
        let udprelay = UdpRelayServer::new(config.clone());
        RelayServer {
            tcprelay: tcprelay,
            udprelay: udprelay,
            enable_udp: config.enable_udp,
        }
    }

    #[cfg(not(feature = "enable-udp"))]
    pub fn new(config: Config) -> RelayServer {
        let tcprelay = TcpRelayServer::new(config.clone());
        RelayServer {
            tcprelay: tcprelay,
            enable_udp: config.enable_udp,
        }
    }
}

impl Relay for RelayServer {
    #[cfg(feature = "enable-udp")]
    fn run(&self) {
        let mut futs = Vec::new();

        let tcprelay = self.tcprelay.clone();
        let tcp_fut = Builder::new().stack_size(COROUTINE_STACK_SIZE).spawn(move || tcprelay.run());
        info!("Enabled TCP relay");
        futs.push(tcp_fut);

        if self.enable_udp {
            let udprelay = self.udprelay.clone();
            let udp_fut = Builder::new().stack_size(COROUTINE_STACK_SIZE).spawn(move || udprelay.run());
            info!("Enabled UDP relay");
            futs.push(udp_fut);
        }

        for fut in futs {
            fut.join().unwrap();
        }
    }

    #[cfg(not(feature = "enable-udp"))]
    fn run(&self) {
        if self.enable_udp {
            warn!("UDP relay feature is disabled, recompile with feature=\"enable-udp\" to enable this feature");
        }

        let tcprelay = self.tcprelay.clone();
        let fut = Builder::new().stack_size(COROUTINE_STACK_SIZE).spawn(move || tcprelay.run());
        info!("Enabled TCP relay");

        fut.join().unwrap();
    }
}
