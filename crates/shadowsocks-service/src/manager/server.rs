//! Shadowsocks Manager server

#[cfg(unix)]
use std::path::PathBuf;
use std::{collections::HashMap, io, net::SocketAddr, sync::Arc, time::Duration};

use log::{error, info, trace};
use shadowsocks::{
    config::{Mode, ServerConfig, ServerType, ServerUser, ServerUserManager},
    context::{Context, SharedContext},
    crypto::CipherKind,
    dns_resolver::DnsResolver,
    manager::protocol::{
        self, AddRequest, AddResponse, ErrorResponse, ListResponse, ManagerRequest, PingResponse, RemoveRequest,
        RemoveResponse, ServerUserConfig, StatRequest,
    },
    net::{AcceptOpts, ConnectOpts},
    plugin::PluginConfig,
    ManagerListener, ServerAddr,
};
use tokio::{sync::Mutex, task::JoinHandle};

use crate::{
    acl::AccessControl,
    config::{ManagerConfig, ManagerServerHost, ManagerServerMode, SecurityConfig},
    net::FlowStat,
    server::Server,
};

enum ServerInstanceMode {
    Builtin {
        flow_stat: Arc<FlowStat>,
        abortable: JoinHandle<io::Result<()>>,
    },

    #[cfg(unix)]
    Standalone { flow_stat: u64 },
}

struct ServerInstance {
    mode: ServerInstanceMode,
    svr_cfg: ServerConfig,
}

impl Drop for ServerInstance {
    fn drop(&mut self) {
        #[allow(irrefutable_let_patterns)]
        if let ServerInstanceMode::Builtin { ref abortable, .. } = self.mode {
            abortable.abort();
        }
    }
}

impl ServerInstance {
    fn flow_stat(&self) -> u64 {
        match self.mode {
            ServerInstanceMode::Builtin { ref flow_stat, .. } => flow_stat.tx() + flow_stat.rx(),
            #[cfg(unix)]
            ServerInstanceMode::Standalone { flow_stat } => flow_stat,
        }
    }
}

/// Manager server
pub struct Manager {
    context: SharedContext,
    servers: Mutex<HashMap<u16, ServerInstance>>,
    svr_cfg: ManagerConfig,
    connect_opts: ConnectOpts,
    accept_opts: AcceptOpts,
    udp_expiry_duration: Option<Duration>,
    udp_capacity: Option<usize>,
    acl: Option<Arc<AccessControl>>,
    ipv6_first: bool,
    security: SecurityConfig,
    worker_count: usize,
}

impl Manager {
    /// Create a new manager server from configuration
    pub fn new(svr_cfg: ManagerConfig) -> Manager {
        Manager::with_context(svr_cfg, Context::new_shared(ServerType::Server))
    }

    /// Create a new manager server with context and configuration
    pub(crate) fn with_context(svr_cfg: ManagerConfig, context: SharedContext) -> Manager {
        Manager {
            context,
            servers: Mutex::new(HashMap::new()),
            svr_cfg,
            connect_opts: ConnectOpts::default(),
            accept_opts: AcceptOpts::default(),
            udp_expiry_duration: None,
            udp_capacity: None,
            acl: None,
            ipv6_first: false,
            security: SecurityConfig::default(),
            worker_count: 1,
        }
    }

    /// Set `ConnectOpts`
    pub fn set_connect_opts(&mut self, opts: ConnectOpts) {
        self.connect_opts = opts;
    }

    /// Set `AcceptOpts`
    pub fn set_accept_opts(&mut self, opts: AcceptOpts) {
        self.accept_opts = opts;
    }

    /// Set UDP association's expiry duration
    pub fn set_udp_expiry_duration(&mut self, d: Duration) {
        self.udp_expiry_duration = Some(d);
    }

    /// Set total UDP associations to be kept in one server
    pub fn set_udp_capacity(&mut self, c: usize) {
        self.udp_capacity = Some(c);
    }

    /// Get the manager's configuration
    pub fn config(&self) -> &ManagerConfig {
        &self.svr_cfg
    }

    /// Get customized DNS resolver
    pub fn set_dns_resolver(&mut self, resolver: Arc<DnsResolver>) {
        let context = Arc::get_mut(&mut self.context).expect("cannot set DNS resolver on a shared context");
        context.set_dns_resolver(resolver)
    }

    /// Set access control list
    pub fn set_acl(&mut self, acl: Arc<AccessControl>) {
        self.acl = Some(acl);
    }

    /// Try to connect IPv6 addresses first if hostname could be resolved to both IPv4 and IPv6
    pub fn set_ipv6_first(&mut self, ipv6_first: bool) {
        self.ipv6_first = ipv6_first;
    }

    /// Set security config
    pub fn set_security_config(&mut self, security: SecurityConfig) {
        self.security = security;
    }

    /// Set runtime worker count
    ///
    /// Should be replaced with tokio's metric API when it is stablized.
    /// https://github.com/tokio-rs/tokio/issues/4073
    pub fn set_worker_count(&mut self, worker_count: usize) {
        self.worker_count = worker_count;
    }

    /// Start serving
    pub async fn run(self) -> io::Result<()> {
        let mut listener = ManagerListener::bind(&self.context, &self.svr_cfg.addr).await?;

        let local_addr = listener.local_addr()?;
        info!("shadowsocks manager server listening on {}", local_addr);

        loop {
            let (req, peer_addr) = match listener.recv_from().await {
                Ok(r) => r,
                Err(err) => {
                    error!("manager recv_from error: {}", err);
                    continue;
                }
            };

            trace!("received {:?} from {:?}", req, peer_addr);

            match req {
                ManagerRequest::Add(ref req) => match self.handle_add(req).await {
                    Ok(rsp) => {
                        let _ = listener.send_to(&rsp, &peer_addr).await;
                    }
                    Err(err) => {
                        error!("add server_port: {} failed, error: {}", req.server_port, err);
                        let rsp = ErrorResponse(err);
                        let _ = listener.send_to(&rsp, &peer_addr).await;
                    }
                },
                ManagerRequest::Remove(ref req) => {
                    let rsp = self.handle_remove(req).await;
                    let _ = listener.send_to(&rsp, &peer_addr).await;
                }
                ManagerRequest::List(..) => {
                    let rsp = self.handle_list().await;
                    let _ = listener.send_to(&rsp, &peer_addr).await;
                }
                ManagerRequest::Ping(..) => {
                    let rsp = self.handle_ping().await;
                    let _ = listener.send_to(&rsp, &peer_addr).await;
                }
                ManagerRequest::Stat(ref stat) => self.handle_stat(stat).await,
            }
        }
    }

    pub async fn add_server(&self, svr_cfg: ServerConfig) {
        match self.svr_cfg.server_mode {
            ManagerServerMode::Builtin => self.add_server_builtin(svr_cfg).await,
            #[cfg(unix)]
            ManagerServerMode::Standalone => self.add_server_standalone(svr_cfg).await,
        }
    }

    async fn add_server_builtin(&self, svr_cfg: ServerConfig) {
        // Each server should use a separate Context, but shares
        //
        // * AccessControlList
        // * DNS Resolver
        let mut server = Server::new(svr_cfg.clone());

        server.set_connect_opts(self.connect_opts.clone());
        server.set_accept_opts(self.accept_opts.clone());
        server.set_dns_resolver(self.context.dns_resolver().clone());

        if let Some(d) = self.udp_expiry_duration {
            server.set_udp_expiry_duration(d);
        }

        if let Some(c) = self.udp_capacity {
            server.set_udp_capacity(c);
        }

        if let Some(ref acl) = self.acl {
            server.set_acl(acl.clone());
        }

        if self.ipv6_first {
            server.set_ipv6_first(self.ipv6_first);
        }

        server.set_security_config(&self.security);

        server.set_worker_count(self.worker_count);

        let server_port = server.config().addr().port();

        let mut servers = self.servers.lock().await;
        // Close existed server
        if let Some(v) = servers.remove(&server_port) {
            info!(
                "closed managed server listening on {}, inbound address {}",
                v.svr_cfg.addr(),
                v.svr_cfg.external_addr()
            );
        }

        let flow_stat = server.flow_stat();

        let abortable = tokio::spawn(async move { server.run().await });

        servers.insert(
            server_port,
            ServerInstance {
                mode: ServerInstanceMode::Builtin { flow_stat, abortable },
                svr_cfg,
            },
        );
    }

    #[cfg(unix)]
    fn server_pid_path(&self, port: u16) -> PathBuf {
        let pid_file_name = format!("shadowsocks-server-{}.pid", port);
        let mut pid_path = self.svr_cfg.server_working_directory.clone();
        pid_path.push(&pid_file_name);
        pid_path
    }

    #[cfg(unix)]
    fn server_config_path(&self, port: u16) -> PathBuf {
        let config_file_name = format!("shadowsocks-server-{}.json", port);
        let mut config_file_path = self.svr_cfg.server_working_directory.clone();
        config_file_path.push(&config_file_name);
        config_file_path
    }

    #[cfg(unix)]
    fn kill_standalone_server(&self, port: u16) {
        use log::{debug, warn};
        use std::{
            fs::{self, File},
            io::Read,
        };

        let pid_path = self.server_pid_path(port);
        if pid_path.exists() {
            if let Ok(mut pid_file) = File::open(&pid_path) {
                let mut pid_content = String::new();
                if let Ok(..) = pid_file.read_to_string(&mut pid_content) {
                    let pid_content = pid_content.trim();

                    match pid_content.parse::<libc::pid_t>() {
                        Ok(pid) => {
                            let _ = unsafe { libc::kill(pid, libc::SIGTERM) };
                            debug!("killed standalone server port {}, pid: {}", port, pid);
                        }
                        Err(..) => {
                            warn!("failed to read pid from {}", pid_path.display());
                        }
                    }
                }
            }
        }

        let server_config_path = self.server_config_path(port);

        let _ = fs::remove_file(&pid_path);
        let _ = fs::remove_file(&server_config_path);
    }

    #[cfg(unix)]
    async fn add_server_standalone(&self, svr_cfg: ServerConfig) {
        use std::{
            fs::{self, OpenOptions},
            io::Write,
        };

        use tokio::process::Command;

        use crate::config::{Config, ConfigType, ServerInstanceConfig};

        // Lock the map first incase there are multiple requests to create one server instance
        let mut servers = self.servers.lock().await;

        // Check if working_directory exists
        if !self.svr_cfg.server_working_directory.exists() {
            fs::create_dir_all(&self.svr_cfg.server_working_directory).expect("create working_directory");
        }

        let port = svr_cfg.addr().port();

        // Check if there is already a running process
        self.kill_standalone_server(port);

        // Create configuration file for server
        let config_file_path = self.server_config_path(port);
        let pid_path = self.server_pid_path(port);

        let server_instance = ServerInstanceConfig {
            config: svr_cfg.clone(),
            acl: None, // Set with --acl command line argument
        };

        let mut config = Config::new(ConfigType::Server);
        config.server.push(server_instance);

        trace!("created standalone server with config {:?}", config);

        let config_file_content = format!("{}", config);

        match OpenOptions::new().write(true).create(true).open(&config_file_path) {
            Err(err) => {
                error!(
                    "failed to open {} for writing, error: {}",
                    config_file_path.display(),
                    err
                );
                return;
            }
            Ok(mut file) => {
                if let Err(err) = file.write_all(config_file_content.as_bytes()) {
                    error!("failed to write {}, error: {}", config_file_path.display(), err);
                    return;
                }
                let _ = file.sync_data();
            }
        }

        let manager_addr = self.svr_cfg.addr.to_string();

        // Start server process
        let mut child_command = Command::new(&self.svr_cfg.server_program);
        child_command
            .arg("-c")
            .arg(&config_file_path)
            .arg("--daemonize")
            .arg("--daemonize-pid")
            .arg(&pid_path)
            .arg("--manager-addr")
            .arg(&manager_addr);

        if let Some(ref acl) = self.acl {
            child_command.arg("--acl").arg(acl.file_path().to_str().expect("acl"));
        }

        let child_result = child_command.kill_on_drop(false).spawn();

        if let Err(err) = child_result {
            error!(
                "failed to spawn process of {}, error: {}",
                self.svr_cfg.server_program, err
            );
            return;
        }

        // Greate. Record into the map
        servers.insert(
            port,
            ServerInstance {
                mode: ServerInstanceMode::Standalone { flow_stat: 0 },
                svr_cfg,
            },
        );
    }

    async fn handle_add(&self, req: &AddRequest) -> io::Result<AddResponse> {
        let addr = match self.svr_cfg.server_host {
            ManagerServerHost::Domain(ref dname) => ServerAddr::DomainName(dname.clone(), req.server_port),
            ManagerServerHost::Ip(ip) => ServerAddr::SocketAddr(SocketAddr::new(ip, req.server_port)),
        };

        let method = match req.method {
            Some(ref m) => match m.parse::<CipherKind>() {
                Ok(method) => method,
                Err(..) => {
                    error!("unrecognized method \"{}\", req: {:?}", m, req);

                    let err = format!("unrecognized method \"{}\"", m);
                    return Ok(AddResponse(err));
                }
            },
            None => self.svr_cfg.method.unwrap_or(CipherKind::CHACHA20_POLY1305),
        };

        let mut svr_cfg = ServerConfig::new(addr, req.password.clone(), method);

        if let Some(ref plugin) = req.plugin {
            let p = PluginConfig {
                plugin: plugin.clone(),
                plugin_opts: req.plugin_opts.clone(),
                plugin_args: Vec::new(),
            };
            svr_cfg.set_plugin(p);
        } else if let Some(ref plugin) = self.svr_cfg.plugin {
            svr_cfg.set_plugin(plugin.clone());
        }

        let mode = match req.mode {
            None => None,
            Some(ref mode) => match mode.parse::<Mode>() {
                Ok(m) => Some(m),
                Err(..) => {
                    error!("unrecognized mode \"{}\", req: {:?}", mode, req);

                    let err = format!("unrecognized mode \"{}\"", mode);
                    return Ok(AddResponse(err));
                }
            },
        };

        svr_cfg.set_mode(mode.unwrap_or(self.svr_cfg.mode));

        if let Some(ref users) = req.users {
            let mut user_manager = ServerUserManager::new();

            for user in users.iter() {
                let user = match ServerUser::with_encoded_key(&user.name, &user.password) {
                    Ok(u) => u,
                    Err(..) => {
                        error!(
                            "users[].password must be encoded with base64, but found: {}",
                            user.password
                        );

                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "users[].password must be encoded with base64",
                        ));
                    }
                };

                user_manager.add_user(user);
            }

            svr_cfg.set_user_manager(user_manager);
        }

        self.add_server(svr_cfg).await;

        Ok(AddResponse("ok".to_owned()))
    }

    async fn handle_remove(&self, req: &RemoveRequest) -> RemoveResponse {
        let mut servers = self.servers.lock().await;
        servers.remove(&req.server_port);

        #[cfg(unix)]
        if self.svr_cfg.server_mode == ManagerServerMode::Standalone {
            self.kill_standalone_server(req.server_port);
        }

        RemoveResponse("ok".to_owned())
    }

    async fn handle_list(&self) -> ListResponse {
        let instances = self.servers.lock().await;

        let mut servers = Vec::new();

        for (_, server) in instances.iter() {
            let svr_cfg = &server.svr_cfg;

            let mut users = None;
            if let Some(user_manager) = server.svr_cfg.user_manager() {
                let mut vu = Vec::with_capacity(user_manager.user_count());

                for user in user_manager.users_iter() {
                    vu.push(ServerUserConfig {
                        name: user.name().to_owned(),
                        password: user.encoded_key(),
                    });
                }

                users = Some(vu);
            }

            let sc = protocol::ServerConfig {
                server_port: svr_cfg.addr().port(),
                password: svr_cfg.password().to_owned(),
                method: None,
                no_delay: None,
                plugin: None,
                plugin_opts: None,
                mode: None,
                users,
            };
            servers.push(sc);
        }

        ListResponse { servers }
    }

    async fn handle_ping(&self) -> PingResponse {
        let instances = self.servers.lock().await;

        let mut stat = HashMap::new();
        for (port, server) in instances.iter() {
            stat.insert(*port, server.flow_stat());
        }

        PingResponse { stat }
    }

    #[cfg(not(unix))]
    async fn handle_stat(&self, _: &StatRequest) {}

    #[cfg(unix)]
    async fn handle_stat(&self, stat: &StatRequest) {
        use log::warn;
        use std::collections::hash_map::Entry;

        use crate::config::{Config, ConfigType};

        // `stat` is only supported for Standalone mode
        if self.svr_cfg.server_mode != ManagerServerMode::Standalone {
            return;
        }

        let mut instances = self.servers.lock().await;

        // Get or create a new instance then record the data statistic numbers
        for (port, flow) in stat.stat.iter() {
            match instances.entry(*port) {
                Entry::Occupied(mut occ) => match occ.get_mut().mode {
                    ServerInstanceMode::Builtin { .. } => {
                        error!("received `stat` for port {} that is running a builtin server", *port)
                    }
                    ServerInstanceMode::Standalone { ref mut flow_stat } => *flow_stat = *flow,
                },
                Entry::Vacant(vac) => {
                    // Read config from file

                    let server_config_path = self.server_config_path(*port);
                    if !server_config_path.exists() {
                        warn!(
                            "received `stat` for port {} but file {} doesn't exist",
                            *port,
                            server_config_path.display()
                        );
                        continue;
                    }

                    match Config::load_from_file(&server_config_path, ConfigType::Server) {
                        Err(err) => {
                            error!(
                                "failed to load {} for server port {}, error: {}",
                                server_config_path.display(),
                                *port,
                                err
                            );
                            continue;
                        }
                        Ok(config) => {
                            trace!(
                                "loaded {} for server port {}, {:?}",
                                server_config_path.display(),
                                *port,
                                config
                            );

                            if config.server.len() != 1 {
                                error!(
                                    "invalid config {} for server port {}, containing {} servers",
                                    server_config_path.display(),
                                    *port,
                                    config.server.len()
                                );
                                continue;
                            }

                            let svr_cfg = config.server[0].config.clone();

                            vac.insert(ServerInstance {
                                mode: ServerInstanceMode::Standalone { flow_stat: *flow },
                                svr_cfg,
                            });
                        }
                    }
                }
            }
        }
    }
}
