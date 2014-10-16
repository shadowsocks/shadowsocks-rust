extern crate log;

// mod relay;
use relay::Relay;
use relay::Stage;
use relay::{StageInit, StageHello, StageUdpAssoc, StageDns, StageReply, StageStream};
use relay;

// mod config;
use config::Config;

use std::io::{TcpListener};
use std::io::{Acceptor, Listener};
use std::io::net::tcp::{TcpAcceptor, TcpStream};
use std::io::{TimedOut, EndOfFile};
use std::str;
use std::sync::Arc;

pub struct TcpRelayLocal {
    acceptor: TcpAcceptor,
    stage: Stage,
    config: Config,
}

impl TcpRelayLocal {
    pub fn new(c: &Config) -> TcpRelayLocal {
        let acceptor = TcpListener::bind(c.local.as_slice(), c.local_port).unwrap().listen().unwrap();

        TcpRelayLocal {
            acceptor: acceptor,
            stage: StageInit,
            config: c.clone(),
        }
    }

    fn handle_hello(remote_stream: &mut TcpStream) {
        let buf = [relay::SOCK5_VERSION, 1, 1];
        debug!("Sent {} to server", buf.to_vec());
        remote_stream.write(buf);

        let reply = remote_stream.read_exact(2).unwrap();

        debug!("Recv {} from server", reply);

        if reply[0] != relay::SOCK5_VERSION {
            fail!("Invalid sock5 version")
        }

        let method_num = reply[1];

        if method_num == 0xff {
            fail!("Server does not support the encrypt method");
        }
    }

    fn handle_auth(remote_stream: &mut TcpStream) {

    }
}

impl Relay for TcpRelayLocal {
    fn run(&mut self) {
        let server_str_arc = Arc::new(self.config.server.clone());
        let server_port_arc = Arc::new(self.config.server_port.clone());
        let encrypt_password = Arc::new(self.config.password.clone());

        loop {
            let server_str = server_str_arc.clone();
            let server_port = server_port_arc.clone();

            match self.acceptor.accept() {
                Ok(mut stream) => spawn(proc() {
                    info!("Client {} connected", stream.peer_name().unwrap());

                    let server = server_str.as_slice();

                    let mut remote_stream = TcpStream::connect(server, *server_port.deref()).unwrap();
                    TcpRelayLocal::handle_hello(&mut remote_stream);
                    TcpRelayLocal::handle_auth(&mut remote_stream);

                    loop {
                        let mut buf = [0u8, .. 10240];
                        match stream.read(buf) {
                            Ok(len) => {
                                let s = buf.slice_to(len);

                                remote_stream.write(s);
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

                    info!("Client {} disconnected", stream.peer_name().unwrap());

                    drop(stream)
                }),
                Err(e) => {
                    fail!(e)
                }
            }
        }
    }
}

pub struct TcpRelayServer {
    acceptor: TcpAcceptor,
    stage: Stage,
    timeout: Option<u64>,
}

impl TcpRelayServer {
    pub fn new(c: &Config) -> TcpRelayServer {
        let acceptor = TcpListener::bind(c.server.as_slice(), c.server_port).unwrap().listen().unwrap();

        TcpRelayServer {
            acceptor: acceptor,
            stage: StageInit,
            timeout: c.timeout,
        }
    }

    fn accept_loop(&mut self) {
        loop {
            match self.acceptor.accept() {
                Ok(mut stream) => spawn(proc() {
                    info!("Client {} connected", stream.peer_name().unwrap());

                    TcpRelayServer::handle_hello(&mut stream);

                    loop {
                        let mut buf = [0u8, .. 10240];
                        match stream.read(buf) {
                            Ok(len) => {
                                let s = buf.slice_to(len);
                                debug!("{} Received: {}", stream.peer_name().unwrap(), s);
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

                    info!("Client {} disconnected", stream.peer_name().unwrap());

                    drop(stream)
                }),
                Err(e) => {
                    fail!(e)
                }
            }
        }
    }

    fn handle_hello(stream: &mut TcpStream) {
        let first_two_bytes = stream.read_exact(2).unwrap();

        if first_two_bytes[0] != relay::SOCK5_VERSION {
            fail!("Invalid sock5 version");
        } else if first_two_bytes[1] == 0 {
            fail!("Invalid sock5 method number");
        }

        let methods = stream.read_exact(first_two_bytes[1] as uint);

        for m in methods.iter() {
            // Choose
        }

        let chosen_method = 1u8;

        let buf = [relay::SOCK5_VERSION, chosen_method];
        stream.write(buf);
    }
}

impl Relay for TcpRelayServer {
    fn run(&mut self) {
        self.accept_loop()
    }
}
