
use relay::udprelay::server::UdpRelayServer;
use relay::tcprelay::server::TcpRelayServer;
use relay::Relay;
use config::Config;

pub struct RelayServer {
    tcprelay: TcpRelayServer,
    udprelay: UdpRelayServer,
}

impl RelayServer {
    pub fn new(config: Config) -> RelayServer {
        let tcprelay = TcpRelayServer::new(config.clone());
        let udprelay = UdpRelayServer::new(config.clone());
        RelayServer {
            tcprelay: tcprelay,
            udprelay: udprelay,
        }
    }
}

impl Relay for RelayServer {
    fn run(&self) {
        let tcprelay = self.tcprelay.clone();
        let udprelay = self.udprelay.clone();

        spawn(proc() tcprelay.run());
        spawn(proc() udprelay.run());
    }
}
