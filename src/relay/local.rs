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

use coio::Scheduler;

use relay::Relay;
use relay::tcprelay::local::HttpRelayLocal;
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
    enable_udp: bool,
    tcprelay: TcpRelayLocal,
    httprelay: Option<HttpRelayLocal>,
    #[cfg(feature = "enable-udp")]
    udprelay: UdpRelayLocal,
}

impl RelayLocal {
    #[cfg(feature = "enable-udp")]
    pub fn new(config: Config) -> RelayLocal {
        let tcprelay = TcpRelayLocal::new(config.clone());
        let httprelay = if config.http_proxy.is_some() {
            Some(HttpRelayLocal::new(config.clone()))
        } else {
            None
        };
        let udprelay = UdpRelayLocal::new(config.clone());
        RelayLocal {
            tcprelay: tcprelay,
            httprelay: httprelay,
            udprelay: udprelay,
            enable_udp: config.enable_udp,
        }
    }

    #[cfg(not(feature = "enable-udp"))]
    pub fn new(config: Config) -> RelayLocal {
        let tcprelay = TcpRelayLocal::new(config.clone());
        let httprelay = if config.http_proxy.is_some() {
            Some(HttpRelayLocal::new(config.clone()))
        } else {
            None
        };
        RelayLocal {
            tcprelay: tcprelay,
            httprelay: httprelay,
            enable_udp: config.enable_udp,
        }
    }
}

impl Relay for RelayLocal {
    #[cfg(not(feature = "enable-udp"))]
    fn run(&self) {
        if self.enable_udp {
            warn!("UDP relay feature is disabled, recompile with feature=\"enable-udp\" to enable this feature");
        }
        let mut futs = Vec::new();

        let tcprelay = self.tcprelay.clone();
        let tcp_fut = Scheduler::spawn(move || tcprelay.run());
        info!("Enabled TCP relay");
        futs.push(tcp_fut);

        if let Some(ref httprelay) = self.httprelay {
            let httprelay = httprelay.clone();
            let http_fut = Scheduler::spawn(move || httprelay.run());
            info!("Enabled Http relay");
            futs.push(http_fut);
        }

        for fut in futs {
            fut.join().unwrap();
        }
    }

    fn run(&self) {
        let mut futs = Vec::new();

        let tcprelay = self.tcprelay.clone();
        let tcp_fut = Scheduler::spawn(move || tcprelay.run());
        info!("Enabled TCP relay");
        futs.push(tcp_fut);

        if self.enable_udp {
            let udprelay = self.udprelay.clone();
            let udp_fut = Scheduler::spawn(move || udprelay.run());
            info!("Enabled UDP relay");
            futs.push(udp_fut);
        }

        if let Some(ref httprelay) = self.httprelay {
            let httprelay = httprelay.clone();
            let http_fut = Scheduler::spawn(move || httprelay.run());
            info!("Enabled Http relay");
            futs.push(http_fut);
        }

        for fut in futs {
            fut.join().unwrap();
        }
    }
}
