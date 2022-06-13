//! Server launchers

use std::{net::IpAddr, path::PathBuf, process::ExitCode, time::Duration};

use clap::{Arg, ArgGroup, ArgMatches, Command, ErrorKind as ClapErrorKind};
use futures::future::{self, Either};
use log::{info, trace};
use tokio::{self, runtime::Builder};

use shadowsocks_service::{
    acl::AccessControl,
    config::{read_variable_field_value, Config, ConfigType, ManagerConfig},
    run_server,
    shadowsocks::{
        config::{ManagerAddr, Mode, ServerAddr, ServerConfig},
        crypto::{available_ciphers, CipherKind},
        plugin::PluginConfig,
    },
};

#[cfg(feature = "logging")]
use crate::logging;
use crate::{
    config::{Config as ServiceConfig, RuntimeMode},
    monitor,
    validator,
};

/// Defines command line options
pub fn define_command_line_options(mut app: Command<'_>) -> Command<'_> {
    app = app
        .arg(
            Arg::new("CONFIG")
                .short('c')
                .long("config")
                .takes_value(true)
                .help("Shadowsocks configuration file (https://shadowsocks.org/en/config/quick-guide.html)"),
        )
        .arg(
            Arg::new("OUTBOUND_BIND_ADDR")
                .short('b')
                .long("outbound-bind-addr")
                .takes_value(true)
                .alias("bind-addr")
                .validator(validator::validate_ip_addr)
                .help("Bind address, outbound socket will bind this address"),
        )
        .arg(
            Arg::new("OUTBOUND_BIND_INTERFACE")
                .long("outbound-bind-interface")
                .takes_value(true)
                .help("Set SO_BINDTODEVICE / IP_BOUND_IF / IP_UNICAST_IF option for outbound socket"),
        )
        .arg(
            Arg::new("SERVER_ADDR")
                .short('s')
                .long("server-addr")
                .takes_value(true)
                .validator(validator::validate_server_addr)
                .requires("ENCRYPT_METHOD")
                .help("Server address"),
        )
        .arg(
            Arg::new("PASSWORD")
                .short('k')
                .long("password")
                .takes_value(true)
                .requires("SERVER_ADDR")
                .help("Server's password"),
        )
        .arg(
            Arg::new("ENCRYPT_METHOD")
                .short('m')
                .long("encrypt-method")
                .takes_value(true)
                .requires("SERVER_ADDR")
                .possible_values(available_ciphers())
                .help("Server's encryption method"),
        )
        .arg(
            Arg::new("TIMEOUT")
                .long("timeout")
                .takes_value(true)
                .validator(validator::validate_u64)
                .requires("SERVER_ADDR")
                .help("Server's timeout seconds for TCP relay"),
        )
        .group(
            ArgGroup::new("SERVER_CONFIG").arg("SERVER_ADDR")
        )
        .arg(
            Arg::new("UDP_ONLY")
                .short('u')
                .conflicts_with("TCP_AND_UDP")
                .requires("SERVER_ADDR")
                .help("Server mode UDP_ONLY"),
        )
        .arg(
            Arg::new("TCP_AND_UDP")
                .short('U')
                .requires("SERVER_ADDR")
                .help("Server mode TCP_AND_UDP"),
        )
        .arg(
            Arg::new("PLUGIN")
                .long("plugin")
                .takes_value(true)
                .requires("SERVER_ADDR")
                .help("SIP003 (https://shadowsocks.org/en/wiki/Plugin.html) plugin"),
        )
        .arg(
            Arg::new("PLUGIN_OPT")
                .long("plugin-opts")
                .takes_value(true)
                .requires("PLUGIN")
                .help("Set SIP003 plugin options"),
        )
        .arg(Arg::new("MANAGER_ADDR").long("manager-addr").takes_value(true).alias("manager-address").help("ShadowSocks Manager (ssmgr) address, could be \"IP:Port\", \"Domain:Port\" or \"/path/to/unix.sock\""))
        .arg(Arg::new("ACL").long("acl").takes_value(true).help("Path to ACL (Access Control List)"))
        .arg(Arg::new("DNS").long("dns").takes_value(true).help("DNS nameservers, formatted like [(tcp|udp)://]host[:port][,host[:port]]..., or unix:///path/to/dns, or predefined keys like \"google\", \"cloudflare\""))
        .arg(Arg::new("TCP_NO_DELAY").long("tcp-no-delay").alias("no-delay").help("Set TCP_NODELAY option for sockets"))
        .arg(Arg::new("TCP_FAST_OPEN").long("tcp-fast-open").alias("fast-open").help("Enable TCP Fast Open (TFO)"))
        .arg(Arg::new("TCP_KEEP_ALIVE").long("tcp-keep-alive").takes_value(true).validator(validator::validate_u64).help("Set TCP keep alive timeout seconds"))
        .arg(Arg::new("UDP_TIMEOUT").long("udp-timeout").takes_value(true).validator(validator::validate_u64).help("Timeout seconds for UDP relay"))
        .arg(Arg::new("UDP_MAX_ASSOCIATIONS").long("udp-max-associations").takes_value(true).validator(validator::validate_u64).help("Maximum associations to be kept simultaneously for UDP relay"))
        .arg(Arg::new("INBOUND_SEND_BUFFER_SIZE").long("inbound-send-buffer-size").takes_value(true).validator(validator::validate_u32).help("Set inbound sockets' SO_SNDBUF option"))
        .arg(Arg::new("INBOUND_RECV_BUFFER_SIZE").long("inbound-recv-buffer-size").takes_value(true).validator(validator::validate_u32).help("Set inbound sockets' SO_RCVBUF option"))
        .arg(Arg::new("OUTBOUND_SEND_BUFFER_SIZE").long("outbound-send-buffer-size").takes_value(true).validator(validator::validate_u32).help("Set outbound sockets' SO_SNDBUF option"))
        .arg(Arg::new("OUTBOUND_RECV_BUFFER_SIZE").long("outbound-recv-buffer-size").takes_value(true).validator(validator::validate_u32).help("Set outbound sockets' SO_RCVBUF option"))
        .arg(
            Arg::new("IPV6_FIRST")
                .short('6')
                .help("Resolve hostname to IPv6 address first"),
        );

    #[cfg(feature = "logging")]
    {
        app = app
            .arg(
                Arg::new("VERBOSE")
                    .short('v')
                    .multiple_occurrences(true)
                    .help("Set log level"),
            )
            .arg(
                Arg::new("LOG_WITHOUT_TIME")
                    .long("log-without-time")
                    .help("Log without datetime prefix"),
            )
            .arg(
                Arg::new("LOG_CONFIG")
                    .long("log-config")
                    .takes_value(true)
                    .help("log4rs configuration file"),
            );
    }

    #[cfg(unix)]
    {
        app = app
            .arg(Arg::new("DAEMONIZE").short('d').long("daemonize").help("Daemonize"))
            .arg(
                Arg::new("DAEMONIZE_PID_PATH")
                    .long("daemonize-pid")
                    .takes_value(true)
                    .help("File path to store daemonized process's PID"),
            );
    }

    #[cfg(all(unix, not(target_os = "android")))]
    {
        app = app.arg(
            Arg::new("NOFILE")
                .short('n')
                .long("nofile")
                .takes_value(true)
                .help("Set RLIMIT_NOFILE with both soft and hard limit"),
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        app = app.arg(
            Arg::new("OUTBOUND_FWMARK")
                .long("outbound-fwmark")
                .takes_value(true)
                .validator(validator::validate_u32)
                .help("Set SO_MARK option for outbound sockets"),
        );
    }

    #[cfg(target_os = "freebsd")]
    {
        app = app.arg(
            Arg::new("OUTBOUND_USER_COOKIE")
                .long("outbound-user-cookie")
                .takes_value(true)
                .validator(validator::validate_u32)
                .help("Set SO_USER_COOKIE option for outbound sockets"),
        );
    }

    #[cfg(feature = "multi-threaded")]
    {
        app = app
            .arg(
                Arg::new("SINGLE_THREADED")
                    .long("single-threaded")
                    .help("Run the program all in one thread"),
            )
            .arg(
                Arg::new("WORKER_THREADS")
                    .long("worker-threads")
                    .takes_value(true)
                    .validator(validator::validate_usize)
                    .help("Sets the number of worker threads the `Runtime` will use"),
            );
    }

    app
}

/// Program entrance `main`
pub fn main(matches: &ArgMatches) -> ExitCode {
    let (config, runtime) = {
        let config_path_opt = matches.value_of("CONFIG").map(PathBuf::from).or_else(|| {
            if !matches.is_present("SERVER_CONFIG") {
                match crate::config::get_default_config_path() {
                    None => None,
                    Some(p) => {
                        println!("loading default config {:?}", p);
                        Some(p)
                    }
                }
            } else {
                None
            }
        });

        let mut service_config = match config_path_opt {
            Some(ref config_path) => match ServiceConfig::load_from_file(config_path) {
                Ok(c) => c,
                Err(err) => {
                    eprintln!("loading config {:?}, {}", config_path, err);
                    return crate::EXIT_CODE_LOAD_CONFIG_FAILURE.into();
                }
            },
            None => ServiceConfig::default(),
        };
        service_config.set_options(matches);

        #[cfg(feature = "logging")]
        match service_config.log.config_path {
            Some(ref path) => {
                logging::init_with_file(path);
            }
            None => {
                logging::init_with_config("sslocal", &service_config.log);
            }
        }

        trace!("{:?}", service_config);

        let mut config = match config_path_opt {
            Some(cpath) => match Config::load_from_file(&cpath, ConfigType::Server) {
                Ok(cfg) => cfg,
                Err(err) => {
                    eprintln!("loading config {:?}, {}", cpath, err);
                    return crate::EXIT_CODE_LOAD_CONFIG_FAILURE.into();
                }
            },
            None => Config::new(ConfigType::Server),
        };

        if let Some(svr_addr) = matches.value_of("SERVER_ADDR") {
            let method = matches.value_of_t_or_exit::<CipherKind>("ENCRYPT_METHOD");

            let password = match matches.value_of_t::<String>("PASSWORD") {
                Ok(pwd) => read_variable_field_value(&pwd).into(),
                Err(err) => {
                    // NOTE: svr_addr should have been checked by crate::validator
                    if method.is_none() {
                        // If method doesn't need a key (none, plain), then we can leave it empty
                        String::new()
                    } else {
                        match crate::password::read_server_password(svr_addr) {
                            Ok(pwd) => pwd,
                            Err(..) => err.exit(),
                        }
                    }
                }
            };

            let svr_addr = svr_addr.parse::<ServerAddr>().expect("server-addr");
            let timeout = match matches.value_of_t::<u64>("TIMEOUT") {
                Ok(t) => Some(Duration::from_secs(t)),
                Err(ref err) if err.kind() == ClapErrorKind::ArgumentNotFound => None,
                Err(err) => err.exit(),
            };

            let mut sc = ServerConfig::new(svr_addr, password, method);
            if let Some(timeout) = timeout {
                sc.set_timeout(timeout);
            }

            if let Some(p) = matches.value_of("PLUGIN") {
                let plugin = PluginConfig {
                    plugin: p.to_owned(),
                    plugin_opts: matches.value_of("PLUGIN_OPT").map(ToOwned::to_owned),
                    plugin_args: Vec::new(),
                };

                sc.set_plugin(plugin);
            }

            // For historical reason, servers that are created from command-line have to be tcp_only.
            sc.set_mode(Mode::TcpOnly);

            if matches.is_present("UDP_ONLY") {
                sc.set_mode(Mode::UdpOnly);
            }

            if matches.is_present("TCP_AND_UDP") {
                sc.set_mode(Mode::TcpAndUdp);
            }

            config.server.push(sc);
        }

        if matches.is_present("TCP_NO_DELAY") {
            config.no_delay = true;
        }

        if matches.is_present("TCP_FAST_OPEN") {
            config.fast_open = true;
        }

        match matches.value_of_t::<u64>("TCP_KEEP_ALIVE") {
            Ok(keep_alive) => config.keep_alive = Some(Duration::from_secs(keep_alive)),
            Err(ref err) if err.kind() == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        match matches.value_of_t::<u32>("OUTBOUND_FWMARK") {
            Ok(mark) => config.outbound_fwmark = Some(mark),
            Err(ref err) if err.kind() == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }

        #[cfg(target_os = "freebsd")]
        match matches.value_of_t::<u32>("OUTBOUND_USER_COOKIE") {
            Ok(user_cookie) => config.outbound_user_cookie = Some(user_cookie),
            Err(ref err) if err.kind() == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }

        match matches.value_of_t::<String>("OUTBOUND_BIND_INTERFACE") {
            Ok(iface) => config.outbound_bind_interface = Some(iface),
            Err(ref err) if err.kind() == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }

        match matches.value_of_t::<ManagerAddr>("MANAGER_ADDR") {
            Ok(addr) => {
                if let Some(ref mut manager_config) = config.manager {
                    manager_config.addr = addr;
                } else {
                    config.manager = Some(ManagerConfig::new(addr));
                }
            }
            Err(ref err) if err.kind() == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }

        #[cfg(all(unix, not(target_os = "android")))]
        match matches.value_of_t::<u64>("NOFILE") {
            Ok(nofile) => config.nofile = Some(nofile),
            Err(ref err) if err.kind() == ClapErrorKind::ArgumentNotFound => {
                crate::sys::adjust_nofile();
            }
            Err(err) => err.exit(),
        }

        if let Some(acl_file) = matches.value_of("ACL") {
            let acl = match AccessControl::load_from_file(acl_file) {
                Ok(acl) => acl,
                Err(err) => {
                    eprintln!("loading ACL \"{}\", {}", acl_file, err);
                    return crate::EXIT_CODE_LOAD_ACL_FAILURE.into();
                }
            };
            config.acl = Some(acl);
        }

        if let Some(dns) = matches.value_of("DNS") {
            config.set_dns_formatted(dns).expect("dns");
        }

        if matches.is_present("IPV6_FIRST") {
            config.ipv6_first = true;
        }

        match matches.value_of_t::<u64>("UDP_TIMEOUT") {
            Ok(udp_timeout) => config.udp_timeout = Some(Duration::from_secs(udp_timeout)),
            Err(ref err) if err.kind() == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }

        match matches.value_of_t::<usize>("UDP_MAX_ASSOCIATIONS") {
            Ok(udp_max_assoc) => config.udp_max_associations = Some(udp_max_assoc),
            Err(ref err) if err.kind() == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }

        match matches.value_of_t::<u32>("INBOUND_SEND_BUFFER_SIZE") {
            Ok(bs) => config.inbound_send_buffer_size = Some(bs),
            Err(ref err) if err.kind() == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }
        match matches.value_of_t::<u32>("INBOUND_RECV_BUFFER_SIZE") {
            Ok(bs) => config.inbound_recv_buffer_size = Some(bs),
            Err(ref err) if err.kind() == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }
        match matches.value_of_t::<u32>("OUTBOUND_SEND_BUFFER_SIZE") {
            Ok(bs) => config.outbound_send_buffer_size = Some(bs),
            Err(ref err) if err.kind() == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }
        match matches.value_of_t::<u32>("OUTBOUND_RECV_BUFFER_SIZE") {
            Ok(bs) => config.outbound_recv_buffer_size = Some(bs),
            Err(ref err) if err.kind() == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }

        match matches.value_of_t::<IpAddr>("OUTBOUND_BIND_ADDR") {
            Ok(bind_addr) => config.outbound_bind_addr = Some(bind_addr),
            Err(ref err) if err.kind() == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }

        // DONE READING options

        if config.server.is_empty() {
            eprintln!(
                "missing proxy servers, consider specifying it by \
                    --server-addr, --encrypt-method, --password command line option, \
                        or configuration file, check more details in https://shadowsocks.org/en/config/quick-guide.html"
            );
            return ExitCode::SUCCESS;
        }

        if let Err(err) = config.check_integrity() {
            eprintln!("config integrity check failed, {}", err);
            return ExitCode::SUCCESS;
        }

        #[cfg(unix)]
        if matches.is_present("DAEMONIZE") || matches.is_present("DAEMONIZE_PID_PATH") {
            use crate::daemonize;
            daemonize::daemonize(matches.value_of("DAEMONIZE_PID_PATH"));
        }

        info!("shadowsocks server {} build {}", crate::VERSION, crate::BUILD_TIME);

        let mut worker_count = 1;
        let mut builder = match service_config.runtime.mode {
            RuntimeMode::SingleThread => Builder::new_current_thread(),
            #[cfg(feature = "multi-threaded")]
            RuntimeMode::MultiThread => {
                let mut builder = Builder::new_multi_thread();
                if let Some(worker_threads) = service_config.runtime.worker_count {
                    worker_count = worker_threads;
                    builder.worker_threads(worker_threads);
                } else {
                    worker_count = num_cpus::get();
                }

                builder
            }
        };
        config.worker_count = worker_count;

        let runtime = builder.enable_all().build().expect("create tokio Runtime");

        (config, runtime)
    };

    runtime.block_on(async move {
        let abort_signal = monitor::create_signal_monitor();
        let server = run_server(config);

        tokio::pin!(abort_signal);
        tokio::pin!(server);

        match future::select(server, abort_signal).await {
            // Server future resolved without an error. This should never happen.
            Either::Left((Ok(..), ..)) => {
                eprintln!("server exited unexpectedly");
                crate::EXIT_CODE_SERVER_EXIT_UNEXPECTEDLY.into()
            }
            // Server future resolved with error, which are listener errors in most cases
            Either::Left((Err(err), ..)) => {
                eprintln!("server aborted with {}", err);
                crate::EXIT_CODE_SERVER_ABORTED.into()
            }
            // The abort signal future resolved. Means we should just exit.
            Either::Right(_) => ExitCode::SUCCESS,
        }
    })
}
