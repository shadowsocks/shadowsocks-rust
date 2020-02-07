//! Server manager
//!
//! Service for managing multiple relay servers

use std::{
    collections::HashMap,
    io::{self, Error, ErrorKind},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str,
};

use byte_string::ByteStr;
use futures::{future, FutureExt};
use log::{debug, error, trace};
use tokio::{self, net::UdpSocket, runtime::Handle, sync::oneshot};

use crate::{
    config::{Config, ConfigType, Mode, ServerAddr, ServerConfig},
    context::{Context, ServerState},
    crypto::CipherType,
    plugin::PluginConfig,
    relay::{
        dns_resolver::resolve_bind_addr,
        flow::SharedServerFlowStatistic,
        sys::create_udp_socket,
        udprelay::MAXIMUM_UDP_PAYLOAD_SIZE,
    },
};

use super::server::create_server;

mod protocol {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug)]
    pub struct ServerConfig {
        pub server_port: u16,
        pub password: String,
        pub method: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub no_delay: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub plugin: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub plugin_opt: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub mode: Option<String>,
    }

    #[derive(Deserialize, Debug)]
    pub struct RemoveRequest {
        pub server_port: u16,
    }
}

struct ServerInstance {
    config: Config,
    flow_stat: SharedServerFlowStatistic,
    #[allow(dead_code)] // This is not dead_code, dropping watcher_tx will inform server task to quit
    watcher_tx: oneshot::Sender<()>,
}

impl ServerInstance {
    async fn start_server(config: Config, rt: Handle) -> io::Result<ServerInstance> {
        let server_port = config.server[0].addr().port();

        let (watcher_tx, watcher_rx) = oneshot::channel::<()>();
        let (server, flow_stat) = create_server(config.clone(), rt).await?;

        tokio::spawn(async move {
            let _ = future::select(server.boxed(), watcher_rx.boxed()).await;
            debug!("Server listening on port {} exited", server_port);
        });

        trace!("Created server listening on port {}", server_port);

        Ok(ServerInstance {
            config,
            flow_stat,
            watcher_tx,
        })
    }

    fn total_transmission(&self) -> u64 {
        self.flow_stat.tcp().tx() + self.flow_stat.tcp().rx() + self.flow_stat.udp().tx() + self.flow_stat.udp().rx()
    }
}

struct ManagerService {
    socket: UdpSocket,
    servers: HashMap<u16, ServerInstance>,
    rt: Handle,
}

impl ManagerService {
    async fn bind(bind_addr: &SocketAddr, rt: Handle) -> io::Result<ManagerService> {
        let socket = create_udp_socket(bind_addr).await?;

        Ok(ManagerService {
            socket,
            servers: HashMap::new(),
            rt,
        })
    }

    async fn serve(&mut self) -> io::Result<()> {
        let mut buf = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];

        loop {
            let (recv_len, src_addr) = self.socket.recv_from(&mut buf).await?;

            let pkt = &buf[..recv_len];

            // Payload must be UTF-8 encoded, or JSON decode will fail
            let pkt = match str::from_utf8(pkt) {
                Ok(p) => p,
                Err(..) => {
                    error!("Received non-UTF8 encoded packet: {:?}", ByteStr::new(pkt));
                    continue;
                }
            };

            let (action, param) = match pkt.find(':') {
                None => (pkt.trim(), ""),
                Some(idx) => {
                    let (action, param) = pkt.split_at(idx);
                    (action.trim(), param[1..].trim())
                }
            };

            let res = match action {
                "add" => {
                    let p: protocol::ServerConfig = match serde_json::from_str(param) {
                        Ok(p) => p,
                        Err(err) => {
                            error!("Failed to parse parameter for \"add\" command, error: {}", err);
                            continue;
                        }
                    };

                    self.handle_add(p).await
                }
                "remove" => {
                    let p: protocol::RemoveRequest = match serde_json::from_str(param) {
                        Ok(p) => p,
                        Err(err) => {
                            error!("Failed to parse parameter for \"add\" command, error: {}", err);
                            continue;
                        }
                    };

                    self.handle_remove(&p).await
                }
                "list" => self.handle_list().await,
                "ping" => self.handle_ping().await,
                _ => {
                    error!("Unrecognized action \"{}\"", action);
                    continue;
                }
            };

            match res {
                Ok(buf) => {
                    let mut buf = &buf[..];

                    loop {
                        match self.socket.send_to(buf, &src_addr).await {
                            Ok(n) => {
                                if n == buf.len() {
                                    break;
                                } else {
                                    buf = &buf[n..];
                                }
                            }
                            Err(err) => {
                                error!("Failed to send response to {}, error: {:?}", src_addr, err);
                                break;
                            }
                        }
                    }
                }
                Err(err) => {
                    error!("Failed to handle action \"{}\", error: {}", action, err);

                    let errmsg = err.to_string();
                    if let Err(err) = self.socket.send_to(errmsg.as_bytes(), &src_addr).await {
                        error!("Failed to send response to {}, error: {:?}", src_addr, err);
                    }
                }
            }
        }
    }

    async fn handle_add(&mut self, p: protocol::ServerConfig) -> io::Result<Vec<u8>> {
        trace!("ACTION \"add\" {:?}", p);

        let server_port = p.server_port;

        let method = match p.method.parse::<CipherType>() {
            Ok(m) => m,
            Err(..) => {
                let err = Error::new(ErrorKind::Other, format!("unrecognized method \"{}\"", p.method));
                return Err(err);
            }
        };

        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), p.server_port);
        let svr_cfg = ServerConfig::new(
            ServerAddr::from(bind_addr),
            p.password,
            method,
            None,
            match p.plugin {
                Some(pp) => Some(PluginConfig {
                    plugin: pp,
                    plugin_opt: p.plugin_opt,
                }),
                None => None,
            },
        );

        let mut config = Config::new(ConfigType::Server);
        config.server.push(svr_cfg);
        if let Some(mode) = p.mode {
            config.mode = match mode.parse::<Mode>() {
                Ok(m) => m,
                Err(..) => {
                    let err = Error::new(ErrorKind::Other, format!("unrecognized mode \"{}\"", mode));
                    return Err(err);
                }
            };
        }
        if let Some(b) = p.no_delay {
            config.no_delay = b;
        }

        // Close it first
        let _ = self.servers.remove(&server_port);

        let server = ServerInstance::start_server(config, self.rt.clone()).await?;
        self.servers.insert(server_port, server);

        Ok(b"ok\n".to_vec())
    }

    async fn handle_remove(&mut self, p: &protocol::RemoveRequest) -> io::Result<Vec<u8>> {
        trace!("ACTION \"remove\" {:?}", p);

        let _ = self.servers.remove(&p.server_port);
        Ok(b"ok\n".to_vec())
    }

    async fn handle_list(&mut self) -> io::Result<Vec<u8>> {
        let mut buf = String::new();
        buf += "[";
        let mut is_first = true;
        for (_, inst) in self.servers.iter() {
            let config = &inst.config;
            let svr_cfg = &config.server[0];

            let p = protocol::ServerConfig {
                server_port: svr_cfg.addr().port(),
                method: svr_cfg.method().to_string(),
                password: svr_cfg.password().to_string(),
                no_delay: None,
                plugin: None,
                plugin_opt: None,
                mode: None,
            };

            if is_first {
                is_first = false;
            } else {
                buf += ",";
            }

            buf += &serde_json::to_string(&p).expect("Failed to convert server config into JSON");
        }
        buf += "]\n";

        trace!("ACTION \"list\" returns {:?}", ByteStr::new(buf.as_bytes()));

        Ok(buf.into_bytes())
    }

    async fn handle_ping(&mut self) -> io::Result<Vec<u8>> {
        let mut buf = String::new();
        buf += "stat: {";
        let mut is_first = true;
        for (port, inst) in self.servers.iter() {
            if is_first {
                is_first = false;
            } else {
                buf += ",";
            }

            buf += &format!("\"{}\":{}", port, inst.total_transmission());
        }
        buf += "}\n";

        trace!("ACTION \"ping\" returns {:?}", ByteStr::new(buf.as_bytes()));

        Ok(buf.into_bytes())
    }
}

pub async fn run(config: Config, rt: Handle) -> io::Result<()> {
    // Create a context containing a DNS resolver and server running state flag.
    let state = ServerState::new(&config, rt.clone()).await?;
    let context = Context::new_shared(config, state);

    let bind_addr = match context.config().manager_address {
        Some(ref a) => resolve_bind_addr(&*context, a).await?,
        None => {
            let err = Error::new(ErrorKind::Other, "missing `manager_address` in configuration");
            return Err(err);
        }
    };

    let mut service = ManagerService::bind(&bind_addr, rt).await?;
    service.serve().await
}
