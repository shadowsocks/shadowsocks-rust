extern crate log;

// mod relay;
use relay::Relay;
use relay::Stage;
use relay::{StageInit, StageHello, StageUdpAssoc, StageDns, StageReply, StageStream};

// mod config;
use config::Config;

use std::io::TcpListener;
use std::io::{Acceptor, Listener};
use std::io::net::tcp::TcpAcceptor;
use std::io::{TimedOut, EndOfFile};

use std::str;

pub struct TcpRelayLocal {
    acceptor: TcpAcceptor,
    stage: Stage,
    timeout: Option<u64>,
}

impl TcpRelayLocal {
    pub fn new(c: &Config) -> TcpRelayLocal {
        let mut acceptor = TcpListener::bind(c.local.as_slice(), c.local_port).unwrap().listen().unwrap();

        TcpRelayLocal {
            acceptor: acceptor,
            stage: StageInit,
            timeout: c.timeout,
        }
    }

    fn accept_loop(&mut self) {
        loop {
            match self.acceptor.accept() {
                Ok(mut stream) => spawn(proc() {
                    info!("Client {} connected", stream.socket_name().unwrap());

                    loop {
                        let mut buf = [0u8, .. 10240];
                        match stream.read(buf) {
                            Ok(len) => {
                                println!("Len: {}", len)

                                let s = buf.slice_to(len);
                                println!("Received: {}", str::from_utf8(s).unwrap());
                                stream.write(s).unwrap()
                            },
                            Err(err) => {
                                if err.kind == EndOfFile {
                                    break
                                }
                                error!("Err: {}", err);
                                break
                            }
                        }
                    }

                    info!("Client {} disconnected", stream.socket_name().unwrap());

                    drop(stream)
                }),
                Err(e) => {
                    fail!(e)
                }
            }
        }
    }
}

impl Relay for TcpRelayLocal {
    fn run(&mut self) {
        self.accept_loop()
    }
}

pub struct TcpRelayServer;

impl TcpRelayServer {
    pub fn new() -> TcpRelayServer {
        TcpRelayServer
    }

}
