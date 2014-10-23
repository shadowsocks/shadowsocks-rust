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

/* code */
// use relay::udprelay::server::UdpRelayServer;
use relay::tcprelay::server::TcpRelayServer;
use relay::Relay;
use config::Config;

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

        spawn(proc() tcprelay.run());
        // spawn(proc() udprelay.run());
    }
}
