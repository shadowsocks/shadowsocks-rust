
use config::Config;
use relay::Relay;

#[deriving(Clone)]
pub struct UdpRelayServer {
    config: Config
}

impl UdpRelayServer {
    pub fn new(config: Config) -> UdpRelayServer {
        UdpRelayServer {
            config: config
        }
    }
}

impl Relay for UdpRelayServer {
    fn run(&self) {
        unimplemented!();
    }
}
