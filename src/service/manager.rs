use std::{net::IpAddr, path::PathBuf, process, time::Duration};

use clap::{clap_app, App, Arg, ArgMatches, ErrorKind as ClapErrorKind};
use futures::future::{self, Either};
use log::info;
use tokio::{self, runtime::Builder};

#[cfg(unix)]
use shadowsocks_service::config::ManagerServerMode;
use shadowsocks_service::{
    acl::AccessControl,
    config::{Config, ConfigType, ManagerConfig, ManagerServerHost},
    run_manager,
    shadowsocks::{
        config::{ManagerAddr, Mode},
        crypto::v1::{available_ciphers, CipherKind},
        plugin::PluginConfig,
    },
};

#[cfg(feature = "logging")]
use crate::logging;
use crate::{monitor, validator};

/// Defines command line options
pub fn define_command_line_options<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
    let mut app = clap_app!(@app (app)
        (@arg UDP_ONLY: -u conflicts_with[TCP_AND_UDP] "Server mode UDP_ONLY")
        (@arg TCP_AND_UDP: -U conflicts_with[UDP_ONLY] "Server mode TCP_AND_UDP")

        (@arg CONFIG: -c --config +takes_value
            "Shadowsocks configuration file (https://shadowsocks.org/en/config/quick-guide.html), \
                the only required fields are \"manager_address\" and \"manager_port\". \
                Servers defined will be created when process is started.")

        (@arg OUTBOUND_BIND_ADDR: -b --("outbound-bind-addr") +takes_value alias("bind-addr") {validator::validate_ip_addr} "Bind address, outbound socket will bind this address")
        (@arg OUTBOUND_BIND_INTERFACE: --("outbound-bind-interface") +takes_value "Set SO_BINDTODEVICE / IP_BOUND_IF / IP_UNICAST_IF option for outbound socket")
        (@arg SERVER_HOST: -s --("server-host") +takes_value "Host name or IP address of your remote server")

        (@arg MANAGER_ADDR: --("manager-addr") +takes_value alias("manager-address") {validator::validate_manager_addr} "ShadowSocks Manager (ssmgr) address, could be ip:port, domain:port or /path/to/unix.sock")
        (@arg ENCRYPT_METHOD: -m --("encrypt-method") +takes_value possible_values(available_ciphers()) "Default encryption method")
        (@arg TIMEOUT: --timeout +takes_value {validator::validate_u64} "Default timeout seconds for TCP relay")

        (@arg PLUGIN: --plugin +takes_value requires[SERVER_ADDR] "Default SIP003 (https://shadowsocks.org/en/spec/Plugin.html) plugin")
        (@arg PLUGIN_OPT: --("plugin-opts") +takes_value requires[PLUGIN] "Default SIP003 plugin options")

        (@arg ACL: --acl +takes_value "Path to ACL (Access Control List)")
        (@arg DNS: --dns +takes_value "DNS nameservers, formatted like [(tcp|udp)://]host[:port][,host[:port]]..., or unix:///path/to/dns, or predefined keys like \"google\", \"cloudflare\"")

        (@arg TCP_NO_DELAY: --("tcp-no-delay") !takes_value alias("no-delay") "Set TCP_NODELAY option for socket")
        (@arg TCP_FAST_OPEN: --("tcp-fast-open") !takes_value alias("fast-open") "Enable TCP Fast Open (TFO)")
        (@arg TCP_KEEP_ALIVE: --("tcp-keep-alive") +takes_value {validator::validate_u64} "Set TCP keep alive timeout seconds")

        (@arg UDP_TIMEOUT: --("udp-timeout") +takes_value {validator::validate_u64} "Timeout seconds for UDP relay")
        (@arg UDP_MAX_ASSOCIATIONS: --("udp-max-associations") +takes_value {validator::validate_u64} "Maximum associations to be kept simultaneously for UDP relay")

        (@arg INBOUND_SEND_BUFFER_SIZE: --("inbound-send-buffer-size") +takes_value {validator::validate_u32} "Set inbound sockets' SO_SNDBUF option")
        (@arg INBOUND_RECV_BUFFER_SIZE: --("inbound-recv-buffer-size") +takes_value {validator::validate_u32} "Set inbound sockets' SO_RCVBUF option")
        (@arg OUTBOUND_SEND_BUFFER_SIZE: --("outbound-send-buffer-size") +takes_value {validator::validate_u32} "Set outbound sockets' SO_SNDBUF option")
        (@arg OUTBOUND_RECV_BUFFER_SIZE: --("outbound-recv-buffer-size") +takes_value {validator::validate_u32} "Set outbound sockets' SO_RCVBUF option")
    );

    #[cfg(feature = "logging")]
    {
        app = clap_app!(@app (app)
            (@arg VERBOSE: -v ... "Set log level")
            (@arg LOG_WITHOUT_TIME: --("log-without-time") "Log without datetime prefix")
            (@arg LOG_CONFIG: --("log-config") +takes_value "log4rs configuration file")
        );
    }

    #[cfg(unix)]
    {
        app = clap_app!(@app (app)
            (@arg DAEMONIZE: -d --("daemonize") "Daemonize")
            (@arg DAEMONIZE_PID_PATH: --("daemonize-pid") +takes_value "File path to store daemonized process's PID")

            (@arg MANAGER_SERVER_MODE: --("manager-server-mode") +takes_value possible_values(&["builtin", "standalone"]) "Servers that running in builtin or standalone mode")
            (@arg MANAGER_SERVER_WORKING_DIRECTORY: --("manager-server-working-directory") +takes_value "Folder for putting servers' configuration and pid files, default is current directory")
        );
    }

    #[cfg(all(unix, not(target_os = "android")))]
    {
        app = clap_app!(@app (app)
            (@arg NOFILE: -n --nofile +takes_value "Set RLIMIT_NOFILE with both soft and hard limit")
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        app = clap_app!(@app (app)
            (@arg OUTBOUND_FWMARK: --("outbound-fwmark") +takes_value {validator::validate_u32} "Set SO_MARK option for outbound socket")
        );
    }

    #[cfg(feature = "multi-threaded")]
    {
        app = clap_app!(@app (app)
            (@arg SINGLE_THREADED: --("single-threaded") "Run the program all in one thread")
            (@arg WORKER_THREADS: --("worker-threads") +takes_value {validator::validate_usize} "Sets the number of worker threads the `Runtime` will use")
        );
    }

    // FIXME: -6 is not a identifier, so we cannot build it with clap_app!
    app = app.arg(
        Arg::with_name("IPV6_FIRST")
            .short("6")
            .help("Resolve hostname to IPv6 address first"),
    );

    app
}

/// Program entrance `main`
pub fn main(matches: &ArgMatches<'_>) {
    let (config, runtime) = {
        #[cfg(feature = "logging")]
        match matches.value_of("LOG_CONFIG") {
            Some(path) => {
                logging::init_with_file(path);
            }
            None => {
                logging::init_with_config("ssmanager", &matches);
            }
        }

        let config_path_opt = matches.value_of("CONFIG").map(PathBuf::from).or_else(|| {
            if !matches.is_present("MANAGER_ADDR") {
                crate::config::get_default_config_path()
            } else {
                None
            }
        });

        let mut config = match config_path_opt {
            Some(cpath) => match Config::load_from_file(&cpath, ConfigType::Manager) {
                Ok(cfg) => cfg,
                Err(err) => {
                    eprintln!("loading config \"{}\", {}", cpath.display(), err);
                    process::exit(crate::EXIT_CODE_LOAD_CONFIG_FAILURE);
                }
            },
            None => Config::new(ConfigType::Manager),
        };

        if matches.is_present("TCP_NO_DELAY") {
            config.no_delay = true;
        }

        if matches.is_present("TCP_FAST_OPEN") {
            config.fast_open = true;
        }

        match clap::value_t!(matches.value_of("TCP_KEEP_ALIVE"), u64) {
            Ok(keep_alive) => config.keep_alive = Some(Duration::from_secs(keep_alive)),
            Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        match clap::value_t!(matches.value_of("OUTBOUND_FWMARK"), u32) {
            Ok(mark) => config.outbound_fwmark = Some(mark),
            Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }

        match clap::value_t!(matches.value_of("OUTBOUND_BIND_INTERFACE"), String) {
            Ok(iface) => config.outbound_bind_interface = Some(iface),
            Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }

        match clap::value_t!(matches.value_of("MANAGER_ADDR"), ManagerAddr) {
            Ok(addr) => {
                if let Some(ref mut manager_config) = config.manager {
                    manager_config.addr = addr;
                } else {
                    config.manager = Some(ManagerConfig::new(addr));
                }
            }
            Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }

        if let Some(ref mut manager_config) = config.manager {
            match clap::value_t!(matches.value_of("ENCRYPT_METHOD"), CipherKind) {
                Ok(m) => manager_config.method = Some(m),
                Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
                Err(err) => err.exit(),
            }

            match clap::value_t!(matches.value_of("TIMEOUT"), u64) {
                Ok(t) => manager_config.timeout = Some(Duration::from_secs(t)),
                Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
                Err(err) => err.exit(),
            }

            match clap::value_t!(matches.value_of("SERVER_HOST"), ManagerServerHost) {
                Ok(sh) => manager_config.server_host = sh,
                Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
                Err(err) => err.exit(),
            }

            if let Some(p) = matches.value_of("PLUGIN") {
                manager_config.plugin = Some(PluginConfig {
                    plugin: p.to_owned(),
                    plugin_opts: matches.value_of("PLUGIN_OPT").map(ToOwned::to_owned),
                    plugin_args: Vec::new(),
                });
            }

            #[cfg(unix)]
            match clap::value_t!(matches.value_of("MANAGER_SERVER_MODE"), ManagerServerMode) {
                Ok(server_mode) => manager_config.server_mode = server_mode,
                Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
                Err(err) => err.exit(),
            }

            #[cfg(unix)]
            match clap::value_t!(matches.value_of("MANAGER_SERVER_WORKING_DIRECTORY"), PathBuf) {
                Ok(server_working_directory) => manager_config.server_working_directory = server_working_directory,
                Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
                Err(err) => err.exit(),
            }
        }

        // Overrides
        if matches.is_present("UDP_ONLY") {
            if let Some(ref mut m) = config.manager {
                m.mode = Mode::UdpOnly;
            }
        }

        if matches.is_present("TCP_AND_UDP") {
            if let Some(ref mut m) = config.manager {
                m.mode = Mode::TcpAndUdp;
            }
        }

        #[cfg(all(unix, not(target_os = "android")))]
        match clap::value_t!(matches.value_of("NOFILE"), u64) {
            Ok(nofile) => config.nofile = Some(nofile),
            Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }

        if let Some(acl_file) = matches.value_of("ACL") {
            let acl = match AccessControl::load_from_file(acl_file) {
                Ok(acl) => acl,
                Err(err) => {
                    eprintln!("loading ACL \"{}\", {}", acl_file, err);
                    process::exit(crate::EXIT_CODE_LOAD_ACL_FAILURE);
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

        match clap::value_t!(matches.value_of("UDP_TIMEOUT"), u64) {
            Ok(udp_timeout) => config.udp_timeout = Some(Duration::from_secs(udp_timeout)),
            Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }

        match clap::value_t!(matches.value_of("UDP_MAX_ASSOCIATIONS"), usize) {
            Ok(udp_max_assoc) => config.udp_max_associations = Some(udp_max_assoc),
            Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }

        match clap::value_t!(matches.value_of("INBOUND_SEND_BUFFER_SIZE"), u32) {
            Ok(bs) => config.inbound_send_buffer_size = Some(bs),
            Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }
        match clap::value_t!(matches.value_of("INBOUND_RECV_BUFFER_SIZE"), u32) {
            Ok(bs) => config.inbound_recv_buffer_size = Some(bs),
            Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }
        match clap::value_t!(matches.value_of("OUTBOUND_SEND_BUFFER_SIZE"), u32) {
            Ok(bs) => config.outbound_send_buffer_size = Some(bs),
            Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }
        match clap::value_t!(matches.value_of("OUTBOUND_RECV_BUFFER_SIZE"), u32) {
            Ok(bs) => config.outbound_recv_buffer_size = Some(bs),
            Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }

        match clap::value_t!(matches.value_of("OUTBOUND_BIND_ADDR"), IpAddr) {
            Ok(bind_addr) => config.outbound_bind_addr = Some(bind_addr),
            Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }

        // DONE reading options

        if config.manager.is_none() {
            eprintln!(
                "missing `manager_address`, consider specifying it by --manager-address command line option, \
             or \"manager_address\" and \"manager_port\" keys in configuration file"
            );
            println!("{}", matches.usage());
            return;
        }

        if let Err(err) = config.check_integrity() {
            eprintln!("config integrity check failed, {}", err);
            println!("{}", matches.usage());
            return;
        }

        #[cfg(unix)]
        if matches.is_present("DAEMONIZE") || matches.is_present("DAEMONIZE_PID_PATH") {
            use crate::daemonize;
            daemonize::daemonize(matches.value_of("DAEMONIZE_PID_PATH"));
        }

        info!("shadowsocks manager {} build {}", crate::VERSION, crate::BUILD_TIME);

        #[cfg(feature = "multi-threaded")]
        let mut builder = if matches.is_present("SINGLE_THREADED") {
            Builder::new_current_thread()
        } else {
            let mut builder = Builder::new_multi_thread();
            if let Some(worker_threads) = matches.value_of("WORKER_THREADS") {
                builder.worker_threads(worker_threads.parse::<usize>().expect("worker-threads"));
            }
            builder
        };
        #[cfg(not(feature = "multi-threaded"))]
        let mut builder = Builder::new_current_thread();

        let runtime = builder.enable_all().build().expect("create tokio Runtime");

        (config, runtime)
    };

    runtime.block_on(async move {
        let abort_signal = monitor::create_signal_monitor();
        let server = run_manager(config);

        tokio::pin!(abort_signal);
        tokio::pin!(server);

        match future::select(server, abort_signal).await {
            // Server future resolved without an error. This should never happen.
            Either::Left((Ok(..), ..)) => {
                eprintln!("server exited unexpectedly");
                process::exit(crate::EXIT_CODE_SERVER_EXIT_UNEXPECTEDLY);
            }
            // Server future resolved with error, which are listener errors in most cases
            Either::Left((Err(err), ..)) => {
                eprintln!("server aborted with {}", err);
                process::exit(crate::EXIT_CODE_SERVER_ABORTED);
            }
            // The abort signal future resolved. Means we should just exit.
            Either::Right(_) => (),
        }
    });
}
