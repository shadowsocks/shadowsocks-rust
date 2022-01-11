//! Local server launchers

use std::{net::IpAddr, path::PathBuf, process, time::Duration};

use clap::{App, Arg, ArgMatches, ErrorKind as ClapErrorKind};
use futures::future::{self, Either};
use log::{info, trace};
use tokio::{self, runtime::Builder};

#[cfg(feature = "local-redir")]
use shadowsocks_service::config::RedirType;
#[cfg(any(feature = "local-dns", feature = "local-tunnel"))]
use shadowsocks_service::shadowsocks::relay::socks5::Address;
use shadowsocks_service::{
    acl::AccessControl,
    config::{read_variable_field_value, Config, ConfigType, LocalConfig, ProtocolType},
    create_local,
    local::loadbalancing::PingBalancer,
    shadowsocks::{
        config::{Mode, ServerAddr, ServerConfig},
        crypto::v1::{available_ciphers, CipherKind},
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
pub fn define_command_line_options(mut app: App<'_>) -> App<'_> {
    app = app.arg(
        Arg::new("CONFIG")
            .short('c')
            .long("config")
            .takes_value(true)
            .help("Shadowsocks configuration file (https://shadowsocks.org/en/config/quick-guide.html)"),
    )
    .arg(
        Arg::new("LOCAL_ADDR")
            .short('b')
            .long("local-addr")
            .takes_value(true)
            .validator(validator::validate_server_addr)
            .help("Local address, listen only to this address if specified"),
    )
    .arg(
        Arg::new("UDP_ONLY")
            .short('u')
            .conflicts_with("TCP_AND_UDP")
            .requires("LOCAL_ADDR")
            .help("Server mode UDP_ONLY"),
    )
    .arg(
        Arg::new("TCP_AND_UDP")
            .short('U')
            .help("Server mode TCP_AND_UDP"),
    )
    .arg(
        Arg::new("PROTOCOL")
            .long("protocol")
            .takes_value(true)
            .possible_values(ProtocolType::available_protocols())
            .help("Protocol for communicating with clients (SOCKS5 by default)"),
    )
    .arg(
        Arg::new("UDP_BIND_ADDR")
            .long("udp-bind-addr")
            .takes_value(true)
            .validator(validator::validate_server_addr)
            .help("UDP relay's bind address, default is the same as local-addr"),
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
    .arg(
        Arg::new("PLUGIN")
            .long("plugin")
            .takes_value(true)
            .requires("SERVER_ADDR")
            .help("SIP003 (https://shadowsocks.org/en/spec/Plugin.html) plugin"),
    )
    .arg(
        Arg::new("PLUGIN_OPT")
            .long("plugin-opts")
            .takes_value(true)
            .requires("PLUGIN")
            .help("Set SIP003 plugin options"),
    )
    .arg(
        Arg::new("URL")
            .long("server-url")
            .takes_value(true)
            .validator(validator::validate_server_url)
            .help("Server address in SIP002 (https://shadowsocks.org/en/wiki/SIP002-URI-Scheme.html) URL"),
    )
    .arg(
        Arg::new("ACL")
            .long("acl")
            .takes_value(true)
            .help("Path to ACL (Access Control List)"),
    )
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
    .arg(Arg::new("OUTBOUND_BIND_ADDR").long("outbound-bind-addr").takes_value(true).alias("bind-addr").validator(validator::validate_ip_addr).help("Bind address, outbound socket will bind this address"))
    .arg(Arg::new("OUTBOUND_BIND_INTERFACE").long("outbound-bind-interface").takes_value(true).help("Set SO_BINDTODEVICE / IP_BOUND_IF / IP_UNICAST_IF option for outbound socket"))
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

    #[cfg(feature = "local-tunnel")]
    {
        app = app.arg(
            Arg::new("FORWARD_ADDR")
                .short('f')
                .long("forward-addr")
                .takes_value(true)
                .requires("LOCAL_ADDR")
                .validator(validator::validate_address)
                .required_if_eq("PROTOCOL", "tunnel")
                .help("Forwarding data directly to this address (for tunnel)"),
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

    #[cfg(feature = "local-redir")]
    {
        if RedirType::tcp_default() != RedirType::NotSupported {
            app = app.arg(
                Arg::new("TCP_REDIR")
                    .long("tcp-redir")
                    .takes_value(true)
                    .requires("LOCAL_ADDR")
                    .possible_values(RedirType::tcp_available_types())
                    .help("TCP redir (transparent proxy) type"),
            );
        }

        if RedirType::udp_default() != RedirType::NotSupported {
            app = app.arg(
                Arg::new("UDP_REDIR")
                    .long("udp-redir")
                    .takes_value(true)
                    .requires("LOCAL_ADDR")
                    .possible_values(RedirType::udp_available_types())
                    .help("UDP redir (transparent proxy) type"),
            );
        }
    }

    #[cfg(target_os = "android")]
    {
        app = app.arg(
            Arg::new("VPN_MODE")
                .long("vpn")
                .help("Enable VPN mode (only for Android)"),
        );
    }

    #[cfg(feature = "local-flow-stat")]
    {
        app = app.arg(
            Arg::new("STAT_PATH")
                .long("stat-path")
                .takes_value(true)
                .help("Specify socket path (unix domain socket) for sending traffic statistic"),
        );
    }

    #[cfg(feature = "local-dns")]
    {
        app = app
            .arg(
                Arg::new("LOCAL_DNS_ADDR")
                    .long("local-dns-addr")
                    .takes_value(true)
                    .required_if_eq("PROTOCOL", "dns")
                    .requires("LOCAL_ADDR")
                    .validator(validator::validate_name_server_addr)
                    .help("Specify the address of local DNS server, send queries directly"),
            )
            .arg(
                Arg::new("REMOTE_DNS_ADDR")
                    .long("remote-dns-addr")
                    .takes_value(true)
                    .required_if_eq("PROTOCOL", "dns")
                    .requires("LOCAL_ADDR")
                    .validator(validator::validate_address)
                    .help("Specify the address of remote DNS server, send queries through shadowsocks' tunnel"),
            );

        #[cfg(target_os = "android")]
        {
            app = app.arg(
                Arg::new("DNS_LOCAL_ADDR")
                    .long("dns-addr")
                    .takes_value(true)
                    .requires_all(&["LOCAL_ADDR", "REMOTE_DNS_ADDR"])
                    .validator(validator::validate_server_addr)
                    .help("DNS address, listen to this address if specified"),
            );
        }
    }

    #[cfg(feature = "local-tun")]
    {
        app = app
            .arg(
                Arg::new("TUN_INTERFACE_NAME")
                    .long("tun-interface-name")
                    .takes_value(true)
                    .help("Tun interface name, allocate one if not specify"),
            )
            .arg(
                Arg::new("TUN_INTERFACE_ADDRESS")
                    .long("tun-interface-address")
                    .takes_value(true)
                    .validator(validator::validate_ipnet)
                    .help("Tun interface address (network)"),
            );

        #[cfg(unix)]
        {
            app = app.arg(
                Arg::new("TUN_DEVICE_FD_FROM_PATH")
                    .long("tun-device-fd-from-path")
                    .takes_value(true)
                    .help("Tun device file descriptor will be transferred from this unix domain socket path"),
            );
        }
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
pub fn main(matches: &ArgMatches) {
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
                    process::exit(crate::EXIT_CODE_LOAD_CONFIG_FAILURE);
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
            Some(cpath) => match Config::load_from_file(&cpath, ConfigType::Local) {
                Ok(cfg) => cfg,
                Err(err) => {
                    eprintln!("loading config {:?}, {}", cpath, err);
                    process::exit(crate::EXIT_CODE_LOAD_CONFIG_FAILURE);
                }
            },
            None => Config::new(ConfigType::Local),
        };

        if let Some(svr_addr) = matches.value_of("SERVER_ADDR") {
            let password = match matches.value_of_t::<String>("PASSWORD") {
                Ok(pwd) => read_variable_field_value(&pwd).into(),
                Err(err) => {
                    // NOTE: svr_addr should have been checked by crate::validator
                    match crate::password::read_server_password(svr_addr) {
                        Ok(pwd) => pwd,
                        Err(..) => err.exit(),
                    }
                }
            };

            let method = matches.value_of_t_or_exit::<CipherKind>("ENCRYPT_METHOD");
            let svr_addr = svr_addr.parse::<ServerAddr>().expect("server-addr");

            let timeout = match matches.value_of_t::<u64>("TIMEOUT") {
                Ok(t) => Some(Duration::from_secs(t)),
                Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => None,
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

            config.server.push(sc);
        }

        match matches.value_of_t::<ServerConfig>("URL") {
            Ok(svr_addr) => config.server.push(svr_addr),
            Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }

        #[cfg(feature = "local-flow-stat")]
        {
            if let Some(stat_path) = matches.value_of("STAT_PATH") {
                config.stat_path = Some(From::from(stat_path));
            }
        }

        #[cfg(target_os = "android")]
        if matches.is_present("VPN_MODE") {
            // A socket `protect_path` in CWD
            // Same as shadowsocks-libev's android.c
            config.outbound_vpn_protect_path = Some(From::from("protect_path"));
        }

        if matches.value_of("LOCAL_ADDR").is_some() || matches.value_of("PROTOCOL").is_some() {
            let protocol = match matches.value_of("PROTOCOL") {
                Some("socks") => ProtocolType::Socks,
                #[cfg(feature = "local-http")]
                Some("http") => ProtocolType::Http,
                #[cfg(feature = "local-tunnel")]
                Some("tunnel") => ProtocolType::Tunnel,
                #[cfg(feature = "local-redir")]
                Some("redir") => ProtocolType::Redir,
                #[cfg(feature = "local-dns")]
                Some("dns") => ProtocolType::Dns,
                #[cfg(feature = "local-tun")]
                Some("tun") => ProtocolType::Tun,
                Some(p) => panic!("not supported `protocol` \"{}\"", p),
                None => ProtocolType::Socks,
            };

            let mut local_config = LocalConfig::new(protocol);
            match matches.value_of_t::<ServerAddr>("LOCAL_ADDR") {
                Ok(local_addr) => local_config.addr = Some(local_addr),
                Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {
                    #[cfg(feature = "local-tun")]
                    if protocol == ProtocolType::Tun {
                        // `tun` protocol doesn't need --local-addr
                    } else {
                        err.exit();
                    }
                }
                Err(err) => err.exit(),
            }

            match matches.value_of_t::<ServerAddr>("UDP_BIND_ADDR") {
                Ok(udp_bind_addr) => local_config.udp_addr = Some(udp_bind_addr),
                Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
                Err(err) => err.exit(),
            }

            #[cfg(feature = "local-tunnel")]
            match matches.value_of_t::<Address>("FORWARD_ADDR") {
                Ok(addr) => local_config.forward_addr = Some(addr),
                Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
                Err(err) => err.exit(),
            }

            #[cfg(feature = "local-redir")]
            {
                match matches.value_of_t::<RedirType>("TCP_REDIR") {
                    Ok(tcp_redir) => local_config.tcp_redir = tcp_redir,
                    Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
                    Err(err) => err.exit(),
                }

                match matches.value_of_t::<RedirType>("UDP_REDIR") {
                    Ok(udp_redir) => local_config.udp_redir = udp_redir,
                    Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
                    Err(err) => err.exit(),
                }
            }

            #[cfg(feature = "local-dns")]
            {
                use shadowsocks_service::{local::dns::NameServerAddr, shadowsocks::relay::socks5::AddressError};
                use std::{net::SocketAddr, str::FromStr};

                struct RemoteDnsAddress(Address);

                impl FromStr for RemoteDnsAddress {
                    type Err = AddressError;

                    fn from_str(a: &str) -> Result<RemoteDnsAddress, Self::Err> {
                        if let Ok(ip) = a.parse::<IpAddr>() {
                            return Ok(RemoteDnsAddress(Address::SocketAddress(SocketAddr::new(ip, 53))));
                        }

                        if let Ok(saddr) = a.parse::<SocketAddr>() {
                            return Ok(RemoteDnsAddress(Address::SocketAddress(saddr)));
                        }

                        if a.find(':').is_some() {
                            a.parse::<Address>().map(RemoteDnsAddress)
                        } else {
                            Ok(RemoteDnsAddress(Address::DomainNameAddress(a.to_owned(), 53)))
                        }
                    }
                }

                match matches.value_of_t::<NameServerAddr>("LOCAL_DNS_ADDR") {
                    Ok(addr) => local_config.local_dns_addr = Some(addr),
                    Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
                    Err(err) => err.exit(),
                }

                match matches.value_of_t::<RemoteDnsAddress>("REMOTE_DNS_ADDR") {
                    Ok(addr) => local_config.remote_dns_addr = Some(addr.0),
                    Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
                    Err(err) => err.exit(),
                }
            }

            #[cfg(all(feature = "local-dns", target_os = "android"))]
            if protocol != ProtocolType::Dns {
                // Start a DNS local server binding to DNS_LOCAL_ADDR
                //
                // This is a special route only for shadowsocks-android
                match matches.value_of_t::<ServerAddr>("DNS_LOCAL_ADDR") {
                    Ok(addr) => {
                        let mut local_dns_config = LocalConfig::new_with_addr(addr, ProtocolType::Dns);

                        // The `local_dns_addr` and `remote_dns_addr` are for this DNS server (for compatibility)
                        local_dns_config.local_dns_addr = local_config.local_dns_addr.take();
                        local_dns_config.remote_dns_addr = local_config.remote_dns_addr.take();

                        config.local.push(local_dns_config);
                    }
                    Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
                    Err(err) => err.exit(),
                }
            }

            #[cfg(feature = "local-tun")]
            {
                use ipnet::IpNet;

                match matches.value_of_t::<IpNet>("TUN_INTERFACE_ADDRESS") {
                    Ok(tun_address) => local_config.tun_interface_address = Some(tun_address),
                    Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
                    Err(err) => err.exit(),
                }
                match matches.value_of_t::<String>("TUN_INTERFACE_NAME") {
                    Ok(tun_name) => local_config.tun_interface_name = Some(tun_name),
                    Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
                    Err(err) => err.exit(),
                }

                #[cfg(unix)]
                match matches.value_of_t::<PathBuf>("TUN_DEVICE_FD_FROM_PATH") {
                    Ok(fd_path) => local_config.tun_device_fd_from_path = Some(fd_path),
                    Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
                    Err(err) => err.exit(),
                }
            }

            if matches.is_present("UDP_ONLY") {
                local_config.mode = Mode::UdpOnly;
            }

            if matches.is_present("TCP_AND_UDP") {
                local_config.mode = Mode::TcpAndUdp;
            }

            config.local.push(local_config);
        }

        if matches.is_present("TCP_NO_DELAY") {
            config.no_delay = true;
        }

        if matches.is_present("TCP_FAST_OPEN") {
            config.fast_open = true;
        }

        match matches.value_of_t::<u64>("TCP_KEEP_ALIVE") {
            Ok(keep_alive) => config.keep_alive = Some(Duration::from_secs(keep_alive)),
            Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        match matches.value_of_t::<u32>("OUTBOUND_FWMARK") {
            Ok(mark) => config.outbound_fwmark = Some(mark),
            Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }

        match matches.value_of_t::<String>("OUTBOUND_BIND_INTERFACE") {
            Ok(iface) => config.outbound_bind_interface = Some(iface),
            Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }

        #[cfg(all(unix, not(target_os = "android")))]
        match matches.value_of_t::<u64>("NOFILE") {
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

        match matches.value_of_t::<u64>("UDP_TIMEOUT") {
            Ok(udp_timeout) => config.udp_timeout = Some(Duration::from_secs(udp_timeout)),
            Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }

        match matches.value_of_t::<usize>("UDP_MAX_ASSOCIATIONS") {
            Ok(udp_max_assoc) => config.udp_max_associations = Some(udp_max_assoc),
            Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }

        match matches.value_of_t::<u32>("INBOUND_SEND_BUFFER_SIZE") {
            Ok(bs) => config.inbound_send_buffer_size = Some(bs),
            Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }
        match matches.value_of_t::<u32>("INBOUND_RECV_BUFFER_SIZE") {
            Ok(bs) => config.inbound_recv_buffer_size = Some(bs),
            Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }
        match matches.value_of_t::<u32>("OUTBOUND_SEND_BUFFER_SIZE") {
            Ok(bs) => config.outbound_send_buffer_size = Some(bs),
            Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }
        match matches.value_of_t::<u32>("OUTBOUND_RECV_BUFFER_SIZE") {
            Ok(bs) => config.outbound_recv_buffer_size = Some(bs),
            Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }

        match matches.value_of_t::<IpAddr>("OUTBOUND_BIND_ADDR") {
            Ok(bind_addr) => config.outbound_bind_addr = Some(bind_addr),
            Err(ref err) if err.kind == ClapErrorKind::ArgumentNotFound => {}
            Err(err) => err.exit(),
        }

        // DONE READING options

        if config.local.is_empty() {
            eprintln!(
                "missing `local_address`, consider specifying it by --local-addr command line option, \
             or \"local_address\" and \"local_port\" in configuration file"
            );
            return;
        }

        if config.server.is_empty() {
            eprintln!(
                "missing proxy servers, consider specifying it by \
             --server-addr, --encrypt-method, --password command line option, \
                or --server-url command line option, \
                or configuration file, check more details in https://shadowsocks.org/en/config/quick-guide.html"
            );
            return;
        }

        if let Err(err) = config.check_integrity() {
            eprintln!("config integrity check failed, {}", err);
            return;
        }

        #[cfg(unix)]
        if matches.is_present("DAEMONIZE") || matches.is_present("DAEMONIZE_PID_PATH") {
            use crate::daemonize;
            daemonize::daemonize(matches.value_of("DAEMONIZE_PID_PATH"));
        }

        info!("shadowsocks local {} build {}", crate::VERSION, crate::BUILD_TIME);

        let mut builder = match service_config.runtime.mode {
            RuntimeMode::SingleThread => Builder::new_current_thread(),
            #[cfg(feature = "multi-threaded")]
            RuntimeMode::MultiThread => {
                let mut builder = Builder::new_multi_thread();
                if let Some(worker_threads) = service_config.runtime.worker_count {
                    builder.worker_threads(worker_threads);
                }

                builder
            }
        };

        let runtime = builder.enable_all().build().expect("create tokio Runtime");

        (config, runtime)
    };

    runtime.block_on(async move {
        let config_path = config.config_path.clone();

        let instance = create_local(config).await.expect("create local");

        if let Some(config_path) = config_path {
            launch_reload_server_task(config_path, instance.server_balancer().clone());
        }

        let abort_signal = monitor::create_signal_monitor();
        let server = instance.run();

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

#[cfg(unix)]
fn launch_reload_server_task(config_path: PathBuf, balancer: PingBalancer) {
    use log::error;
    use tokio::signal::unix::{signal, SignalKind};

    tokio::spawn(async move {
        let mut sigusr1 = signal(SignalKind::user_defined1()).expect("signal");

        while sigusr1.recv().await.is_some() {
            let config = match Config::load_from_file(&config_path, ConfigType::Local) {
                Ok(c) => c,
                Err(err) => {
                    error!("auto-reload {} failed with error: {}", config_path.display(), err);
                    continue;
                }
            };

            let servers = config.server;
            info!("auto-reload {} with {} servers", config_path.display(), servers.len());

            if let Err(err) = balancer.reset_servers(servers).await {
                error!("auto-reload {} but found error: {}", config_path.display(), err);
            }
        }
    });
}

#[cfg(not(unix))]
fn launch_reload_server_task(_: PathBuf, _: PingBalancer) {}
