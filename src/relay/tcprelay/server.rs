
use config::Config;
use relay::Relay;

pub struct TcpRelayServer {
    config: Config,
}

impl TcpRelayServer {
    pub fn new(c: Config) -> TcpRelayServer {
        TcpRelayServer {
            config: c,
        }
    }
}

impl Relay for TcpRelayServer {
    fn run(&self) {

    }
}
