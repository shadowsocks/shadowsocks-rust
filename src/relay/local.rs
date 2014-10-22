
use relay::Relay;
use relay::tcprelay::local::TcpRelayLocal;
use relay::udprelay::local::UdpRelayLocal;
use config::Config;

#[deriving(Clone)]
pub struct RelayLocal {
    tcprelay: TcpRelayLocal,
    udprelay: UdpRelayLocal,
}

impl RelayLocal {
    pub fn new(config: Config) -> RelayLocal {
        let tcprelay = TcpRelayLocal::new(config.clone());
        let udprelay = UdpRelayLocal::new(config.clone());
        RelayLocal {
            tcprelay: tcprelay,
            udprelay: udprelay,
        }
    }
}

impl Relay for RelayLocal {
    fn run(&self) {
        let tcprelay = self.tcprelay.clone();
        spawn(proc() tcprelay.run());

        let udprelay = self.udprelay.clone();
        spawn(proc() udprelay.run());
    }
}
