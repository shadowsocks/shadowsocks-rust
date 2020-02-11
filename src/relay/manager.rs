//! Server manager
//!
//! Service for managing multiple relay servers

#[cfg(unix)]
use std::os::unix::net::SocketAddr as UnixSocketAddr;
use std::{
    collections::HashMap,
    io::{self, Error, ErrorKind},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str,
};

use byte_string::ByteStr;
use futures::{future, FutureExt};
use log::{debug, error, trace, warn};
#[cfg(unix)]
use tokio::net::UnixDatagram;
use tokio::{self, net::UdpSocket, runtime::Handle, sync::oneshot};

use crate::{
    config::{Config, ConfigType, ManagerAddr, Mode, ServerAddr, ServerConfig},
    context::{Context, ServerState, SharedContext, SharedServerState},
    crypto::CipherType,
    plugin::PluginConfig,
    relay::{
        flow::{MultiServerFlowStatistic, SharedServerFlowStatistic},
        sys::create_udp_socket,
        udprelay::MAXIMUM_UDP_PAYLOAD_SIZE,
        utils::set_nofile,
    },
};

use super::server;

mod protocol {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug)]
    pub struct ServerConfig {
        pub server_port: u16,
        pub password: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub method: Option<String>,
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
    async fn start_server(config: Config, server_state: SharedServerState) -> io::Result<ServerInstance> {
        let server_port = config.server[0].addr().port();

        let (watcher_tx, watcher_rx) = oneshot::channel::<()>();

        let flow_stat = MultiServerFlowStatistic::new_shared(&config);

        {
            // Run server in current process, sharing the same tokio runtime
            //
            // NOTE: This may make different users interfere with each other,
            // which means that this is not a good decision

            let config = config.clone();
            let flow_stat = flow_stat.clone();

            tokio::spawn(async move {
                let server = server::run_with(config, flow_stat, server_state);

                let _ = future::select(server.boxed(), watcher_rx.boxed()).await;
                debug!("Server listening on port {} exited", server_port);
            });
        }

        let flow_stat = flow_stat
            .get(server_port)
            .expect("port not existed in multi-server flow statistic")
            .clone();

        trace!("Created server listening on port {}", server_port);

        Ok(ServerInstance {
            config,
            flow_stat,
            watcher_tx,
        })
    }

    fn total_transmission(&self) -> u64 {
        self.flow_stat.tcp().tx()
            + self.flow_stat.tcp().rx()
            + self.flow_stat.udp().tx()
            + self.flow_stat.udp().rx()
            + self.flow_stat.stat()
    }

    fn update_transmission(&self, transmission: u64) {
        // stat command returns a total transmission value
        self.flow_stat.set_stat(transmission);
    }
}

/// Datagram socket for manager
///
/// For *nix system, this is a wrapper for both UDP socket and Unix socket
pub enum ManagerDatagram {
    UdpDatagram(UdpSocket),
    #[cfg(unix)]
    UnixDatagram(UnixDatagram),
}

impl ManagerDatagram {
    /// Create a `ManagerDatagram` binding to requested `bind_addr`
    pub async fn bind(bind_addr: &ManagerAddr, context: &Context) -> io::Result<ManagerDatagram> {
        match *bind_addr {
            ManagerAddr::SocketAddr(ref saddr) => Ok(ManagerDatagram::UdpDatagram(create_udp_socket(saddr).await?)),
            ManagerAddr::DomainName(ref dname, port) => {
                let (_, socket) =
                    lookup_then!(context, dname, port, false, |saddr| { create_udp_socket(&saddr).await })?;

                Ok(ManagerDatagram::UdpDatagram(socket))
            }
            #[cfg(unix)]
            ManagerAddr::UnixSocketAddr(ref path) => {
                use std::fs;

                // Remove it first incase it is already exists
                let _ = fs::remove_file(path);

                Ok(ManagerDatagram::UnixDatagram(UnixDatagram::bind(path)?))
            }
        }
    }

    /// Create a `ManagerDatagram` for sending data to manager
    pub async fn bind_for(bind_addr: &ManagerAddr) -> io::Result<ManagerDatagram> {
        match *bind_addr {
            ManagerAddr::SocketAddr(..) | ManagerAddr::DomainName(..) => {
                // Bind to 0.0.0.0 and let system allocate a port
                let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
                Ok(ManagerDatagram::UdpDatagram(create_udp_socket(&local_addr).await?))
            }
            #[cfg(unix)]
            // For unix socket, it doesn't need to bind to any valid address
            // Because manager won't response to you
            ManagerAddr::UnixSocketAddr(..) => Ok(ManagerDatagram::UnixDatagram(UnixDatagram::unbound()?)),
        }
    }

    /// Receives data from the socket.
    pub async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, ManagerSocketAddr)> {
        match *self {
            ManagerDatagram::UdpDatagram(ref mut udp) => {
                let (s, addr) = udp.recv_from(buf).await?;
                Ok((s, ManagerSocketAddr::SocketAddr(addr)))
            }
            #[cfg(unix)]
            ManagerDatagram::UnixDatagram(ref mut unix) => {
                let (s, addr) = unix.recv_from(buf).await?;
                Ok((s, ManagerSocketAddr::UnixSocketAddr(addr)))
            }
        }
    }

    /// Sends data on the socket to the specified address.
    pub async fn send_to(&mut self, buf: &[u8], target: &ManagerSocketAddr) -> io::Result<usize> {
        match *self {
            ManagerDatagram::UdpDatagram(ref mut udp) => match *target {
                ManagerSocketAddr::SocketAddr(ref saddr) => udp.send_to(buf, saddr).await,
                #[cfg(unix)]
                ManagerSocketAddr::UnixSocketAddr(..) => {
                    let err = Error::new(ErrorKind::InvalidInput, "udp datagram requires IP address target");
                    Err(err)
                }
            },
            #[cfg(unix)]
            ManagerDatagram::UnixDatagram(ref mut unix) => match *target {
                ManagerSocketAddr::UnixSocketAddr(ref saddr) => match saddr.as_pathname() {
                    Some(paddr) => unix.send_to(buf, paddr).await,
                    None => {
                        let err = Error::new(ErrorKind::InvalidInput, "target address must not be unnamed");
                        Err(err)
                    }
                },
                ManagerSocketAddr::SocketAddr(..) => {
                    let err = Error::new(ErrorKind::InvalidInput, "unix datagram requires path address target");
                    Err(err)
                }
            },
        }
    }

    /// Sends data on the socket to the specified manager address
    pub async fn send_to_manager(&mut self, buf: &[u8], context: &Context, target: &ManagerAddr) -> io::Result<usize> {
        match *self {
            ManagerDatagram::UdpDatagram(ref mut udp) => match *target {
                ManagerAddr::SocketAddr(ref saddr) => udp.send_to(buf, saddr).await,
                ManagerAddr::DomainName(ref dname, port) => {
                    let (_, n) = lookup_then!(context, dname, port, false, |saddr| { udp.send_to(buf, saddr).await })?;
                    Ok(n)
                }
                #[cfg(unix)]
                ManagerAddr::UnixSocketAddr(..) => {
                    let err = Error::new(ErrorKind::InvalidInput, "udp datagram requires IP address target");
                    Err(err)
                }
            },
            #[cfg(unix)]
            ManagerDatagram::UnixDatagram(ref mut unix) => match *target {
                ManagerAddr::UnixSocketAddr(ref paddr) => unix.send_to(buf, paddr).await,
                ManagerAddr::SocketAddr(..) | ManagerAddr::DomainName(..) => {
                    let err = Error::new(ErrorKind::InvalidInput, "unix datagram requires path address target");
                    Err(err)
                }
            },
        }
    }
}

/// Target address for manager for representing client connections
#[derive(Debug)]
pub enum ManagerSocketAddr {
    SocketAddr(SocketAddr),
    #[cfg(unix)]
    UnixSocketAddr(UnixSocketAddr),
}

impl ManagerSocketAddr {
    /// Check if it is unnamed (not binded to any valid address), only valid for `UnixSocketAddr`
    pub fn is_unnamed(&self) -> bool {
        match *self {
            ManagerSocketAddr::SocketAddr(..) => false,
            #[cfg(unix)]
            ManagerSocketAddr::UnixSocketAddr(ref s) => s.is_unnamed(),
        }
    }
}

struct ManagerService {
    socket: ManagerDatagram,
    servers: HashMap<u16, ServerInstance>,
    context: SharedContext,
}

impl ManagerService {
    async fn bind(bind_addr: &ManagerAddr, context: SharedContext) -> io::Result<ManagerService> {
        let socket = ManagerDatagram::bind(bind_addr, &*context).await?;

        Ok(ManagerService {
            socket,
            servers: HashMap::new(),
            context,
        })
    }

    async fn serve(&mut self) -> io::Result<()> {
        let mut buf = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];

        loop {
            let (recv_len, src_addr) = self.socket.recv_from(&mut buf).await?;
            let pkt = &buf[..recv_len];

            let resp_pkt = match self.handle_packet(pkt).await {
                Some(p) => p,
                None => continue,
            };

            if src_addr.is_unnamed() {
                trace!(
                    "Received a packet ({} bytes) from an unnamed unix-socket client, \
                     unsound because we are unable to send response back to it",
                    recv_len
                );
                continue;
            }

            let n = match self.socket.send_to(&resp_pkt, &src_addr).await {
                Ok(n) => n,
                Err(err) => {
                    error!("Response send_to failed, destination: {:?}, error: {}", src_addr, err);
                    continue;
                }
            };

            if n != resp_pkt.len() {
                error!(
                    "Response packet truncated, packet: {}, sent: {}, destination: {:?}",
                    resp_pkt.len(),
                    n,
                    src_addr
                );
            }
        }
    }

    async fn handle_packet(&mut self, pkt: &[u8]) -> Option<Vec<u8>> {
        trace!("REQUEST: {:?}", ByteStr::new(pkt));

        // Payload must be UTF-8 encoded, or JSON decode will fail
        let pkt = match str::from_utf8(pkt) {
            Ok(p) => p,
            Err(..) => {
                error!("Received non-UTF8 encoded packet: {:?}", ByteStr::new(pkt));

                return Some(b"invalid encoding".to_vec());
            }
        };

        let (action, param) = match pkt.find(':') {
            None => (pkt.trim(), ""),
            Some(idx) => {
                let (action, param) = pkt.split_at(idx);
                (action.trim(), param[1..].trim())
            }
        };

        match self.dispatch_command(action, param).await {
            Ok(v) => v,
            Err(err) => {
                error!("Failed to handle action \"{}\", error: {}", action, err);

                Some(Vec::from(err.to_string()))
            }
        }
    }

    async fn dispatch_command(&mut self, action: &str, param: &str) -> io::Result<Option<Vec<u8>>> {
        match action {
            "add" => {
                let p: protocol::ServerConfig = match serde_json::from_str(param) {
                    Ok(p) => p,
                    Err(err) => {
                        let err = Error::new(ErrorKind::InvalidData, err);
                        return Err(err);
                    }
                };

                self.handle_add(p).await
            }
            "remove" => {
                let p: protocol::RemoveRequest = match serde_json::from_str(param) {
                    Ok(p) => p,
                    Err(err) => {
                        let err = Error::new(ErrorKind::InvalidData, err);
                        return Err(err);
                    }
                };

                self.handle_remove(&p).await
            }
            "list" => self.handle_list().await,
            "ping" => self.handle_ping().await,
            "stat" => {
                let pmap: HashMap<String, u64> = match serde_json::from_str(param) {
                    Ok(p) => p,
                    Err(err) => {
                        let err = Error::new(ErrorKind::InvalidData, err);
                        return Err(err);
                    }
                };

                self.handle_stat(&pmap).await
            }
            _ => {
                let err = Error::new(ErrorKind::InvalidData, format!("unrecognized command \"{}\"", action));
                Err(err)
            }
        }
    }

    async fn handle_add(&mut self, p: protocol::ServerConfig) -> io::Result<Option<Vec<u8>>> {
        trace!("ACTION \"add\" {:?}", p);

        let server_port = p.server_port;

        let method = match p.method {
            None => self.context
                .config()
                .manager_method
                // Default method as shadowsocks-libev's ss-server
                // Just for compatiblity, some shadowsocks manager relies on this default method
                .unwrap_or(CipherType::ChaCha20IetfPoly1305),
            Some(method) => match method.parse::<CipherType>() {
                Ok(m) => m,
                Err(..) => {
                    let err = Error::new(ErrorKind::Other, format!("unrecognized method \"{}\"", method));
                    return Err(err);
                }
            },
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

        config.local = self.context.config().local.clone();

        if let Some(mode) = p.mode {
            config.mode = match mode.parse::<Mode>() {
                Ok(m) => m,
                Err(..) => {
                    let err = Error::new(ErrorKind::Other, format!("unrecognized mode \"{}\"", mode));
                    return Err(err);
                }
            };
        }

        // TCP_NODELAY
        if let Some(b) = p.no_delay {
            config.no_delay = b;
        } else {
            config.no_delay = self.context.config().no_delay;
        }

        // timeouts
        config.udp_timeout = self.context.config().udp_timeout;
        config.timeout = self.context.config().timeout;

        // Close it first
        let _ = self.servers.remove(&server_port);
        self.start_server_with_config(server_port, config).await?;

        Ok(Some(b"ok\n".to_vec()))
    }

    async fn start_server_with_config(&mut self, server_port: u16, config: Config) -> io::Result<()> {
        let server = ServerInstance::start_server(config, self.context.clone_server_state()).await?;
        self.servers.insert(server_port, server);

        Ok(())
    }

    async fn handle_remove(&mut self, p: &protocol::RemoveRequest) -> io::Result<Option<Vec<u8>>> {
        trace!("ACTION \"remove\" {:?}", p);

        let _ = self.servers.remove(&p.server_port);
        Ok(Some(b"ok\n".to_vec()))
    }

    async fn handle_list(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut buf = String::new();
        buf += "[";
        let mut is_first = true;
        for (_, inst) in self.servers.iter() {
            let config = &inst.config;
            let svr_cfg = &config.server[0];

            let p = protocol::ServerConfig {
                server_port: svr_cfg.addr().port(),
                method: Some(svr_cfg.method().to_string()),
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

        Ok(Some(buf.into_bytes()))
    }

    async fn handle_ping(&mut self) -> io::Result<Option<Vec<u8>>> {
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

        Ok(Some(buf.into_bytes()))
    }

    async fn handle_stat(&mut self, pmap: &HashMap<String, u64>) -> io::Result<Option<Vec<u8>>> {
        trace!("ACTION \"stat\" {:?}", pmap);

        for (sport, trans) in pmap.iter() {
            match sport.parse::<u16>() {
                Err(..) => {
                    error!(
                        "Invalid data in \"stat\" command, expecting a port number, but found \"{}\"",
                        sport
                    );

                    // Just skip, unsound
                    continue;
                }

                Ok(port) => {
                    if let Some(inst) = self.servers.get(&port) {
                        inst.update_transmission(*trans)
                    }
                }
            }
        }

        Ok(None)
    }
}

/// Server manager for supporting [Manage Multiple Users](https://github.com/shadowsocks/shadowsocks/wiki/Manage-Multiple-Users) APIs
pub async fn run(config: Config, rt: Handle) -> io::Result<()> {
    assert!(config.config_type.is_manager());

    if let Some(nofile) = config.nofile {
        debug!("Setting RLIMIT_NOFILE to {}", nofile);
        if let Err(err) = set_nofile(nofile) {
            match err.kind() {
                ErrorKind::PermissionDenied => {
                    warn!("Insufficient permission to change RLIMIT_NOFILE, try to restart as root user");
                }
                ErrorKind::InvalidInput => {
                    warn!("Invalid `nofile` value {}, decrease it and try again", nofile);
                }
                _ => {
                    error!("Failed to set RLIMIT_NOFILE with value {}, error: {}", nofile, err);
                }
            }
            return Err(err);
        }
    }

    // Create a context containing a DNS resolver and server running state flag.
    let state = ServerState::new_shared(&config, rt.clone()).await?;
    let context = Context::new_shared(config, state.clone());

    let bind_addr = match context.config().manager_address {
        Some(ref a) => a,
        None => {
            let err = Error::new(ErrorKind::Other, "missing `manager_address` in configuration");
            return Err(err);
        }
    };

    let mut service = ManagerService::bind(bind_addr, context.clone()).await?;

    // Creates known servers in configuration
    let config = context.config();

    if !config.server.is_empty() {
        for svr_cfg in &config.server {
            let mut clean_config = Config::new(ConfigType::Server);
            clean_config.local = config.local.clone();
            clean_config.mode = config.mode;
            clean_config.no_delay = config.no_delay;
            clean_config.udp_timeout = config.udp_timeout;

            clean_config.server.push(svr_cfg.clone());

            service
                .start_server_with_config(svr_cfg.addr().port(), clean_config)
                .await?;
        }
    }

    service.serve().await
}
