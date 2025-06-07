//! Local server launchers

#[cfg(unix)]
use std::sync::Arc;
use std::{
    future::Future,
    net::IpAddr,
    path::PathBuf,
    process::ExitCode,
    time::{Duration, Instant},
};

use clap::{Arg, ArgAction, ArgGroup, ArgMatches, Command, ValueHint, builder::PossibleValuesParser};
use futures::future::{self, FutureExt};
use log::{error, info, trace};
use tokio::{
    self,
    runtime::{Builder, Runtime},
};

#[cfg(feature = "local-redir")]
use shadowsocks_service::config::RedirType;
#[cfg(feature = "local-tunnel")]
use shadowsocks_service::shadowsocks::relay::socks5::Address;
use shadowsocks_service::{
    acl::AccessControl,
    config::{
        Config, ConfigType, LocalConfig, LocalInstanceConfig, ProtocolType, ServerInstanceConfig,
        read_variable_field_value,
    },
    local::{Server, loadbalancing::PingBalancer},
    shadowsocks::{
        config::{Mode, ServerAddr, ServerConfig, ServerSource},
        crypto::{CipherKind, available_ciphers},
        plugin::PluginConfig,
    },
};

#[cfg(feature = "logging")]
use crate::logging;
use crate::{
    config::{Config as ServiceConfig, RuntimeMode},
    error::{ShadowsocksError, ShadowsocksResult},
    monitor, vparser,
};

#[cfg(feature = "local-dns")]
mod local_value_parser {
    use std::{
        net::{IpAddr, SocketAddr},
        str::FromStr,
    };

    use shadowsocks_service::shadowsocks::relay::socks5::{Address, AddressError};

    #[derive(Debug, Clone)]
    pub struct RemoteDnsAddress(pub Address);

    impl FromStr for RemoteDnsAddress {
        type Err = AddressError;

        fn from_str(a: &str) -> Result<Self, Self::Err> {
            if let Ok(ip) = a.parse::<IpAddr>() {
                return Ok(Self(Address::SocketAddress(SocketAddr::new(ip, 53))));
            }

            if let Ok(saddr) = a.parse::<SocketAddr>() {
                return Ok(Self(Address::SocketAddress(saddr)));
            }

            if a.find(':').is_some() {
                a.parse::<Address>().map(RemoteDnsAddress)
            } else {
                Ok(Self(Address::DomainNameAddress(a.to_owned(), 53)))
            }
        }
    }

    #[inline]
    pub fn parse_remote_dns_address(s: &str) -> Result<RemoteDnsAddress, AddressError> {
        s.parse::<RemoteDnsAddress>()
    }
}

/// Defines command line options
pub fn define_command_line_options(mut app: Command) -> Command {
    app = app.arg(
        Arg::new("CONFIG")
            .short('c')
            .long("config")
            .num_args(1)
            .action(ArgAction::Set)
            .value_parser(clap::value_parser!(PathBuf))
            .value_hint(ValueHint::FilePath)
            .help("Shadowsocks configuration file (https://shadowsocks.org/doc/configs.html)"),
    )
    .arg(
        Arg::new("LOCAL_ADDR")
            .short('b')
            .long("local-addr")
            .num_args(1)
            .action(ArgAction::Set)
            .value_parser(vparser::parse_server_addr)
            .help("Local address, listen only to this address if specified"),
    )
    .arg(
        Arg::new("UDP_ONLY")
            .short('u')
            .action(ArgAction::SetTrue)
            .conflicts_with("TCP_AND_UDP")
            .requires("LOCAL_ADDR")
            .help("Server mode UDP_ONLY"),
    )
    .arg(
        Arg::new("TCP_AND_UDP")
            .short('U')
            .action(ArgAction::SetTrue)
            .help("Server mode TCP_AND_UDP"),
    )
    .arg(
        Arg::new("PROTOCOL")
            .long("protocol")
            .num_args(1)
            .action(ArgAction::Set)
            .value_parser(PossibleValuesParser::new(ProtocolType::available_protocols()))
            .help("Protocol for communicating with clients (SOCKS5 by default)"),
    )
    .arg(
        Arg::new("UDP_BIND_ADDR")
            .long("udp-bind-addr")
            .num_args(1)
            .action(ArgAction::Set)
            .value_parser(vparser::parse_server_addr)
            .help("UDP relay's bind address, default is the same as local-addr"),
    )
    .arg(
        Arg::new("UDP_ASSOCIATE_ADDR")
        .long("udp-associate-addr")
        .num_args(1)
        .action(ArgAction::Set)
        .value_parser(vparser::parse_server_addr)
        .help("UDP relay's externally visible address return in UDP Associate responses"),
    )
    .arg(
        Arg::new("SERVER_ADDR")
            .short('s')
            .long("server-addr")
            .num_args(1)
            .action(ArgAction::Set)
            .requires("ENCRYPT_METHOD")
            .help("Server address"),
    )
    .arg(
        Arg::new("PASSWORD")
            .short('k')
            .long("password")
            .num_args(1)
            .action(ArgAction::Set)
            .requires("SERVER_ADDR")
            .help("Server's password"),
    )
    .arg(
        Arg::new("ENCRYPT_METHOD")
            .short('m')
            .long("encrypt-method")
            .num_args(1)
            .action(ArgAction::Set)
            .requires("SERVER_ADDR")
            .value_parser(PossibleValuesParser::new(available_ciphers()))
            .help("Server's encryption method"),
    )
    .arg(
        Arg::new("TIMEOUT")
            .long("timeout")
            .num_args(1)
            .action(ArgAction::Set)
            .value_parser(clap::value_parser!(u64))
            .requires("SERVER_ADDR")
            .help("Server's timeout seconds for TCP relay"),
    )
    .arg(
        Arg::new("PLUGIN")
            .long("plugin")
            .num_args(1)
            .action(ArgAction::Set)
            .value_hint(ValueHint::CommandName)
            .requires("SERVER_ADDR")
            .help("SIP003 (https://shadowsocks.org/doc/sip003.html) plugin"),
    )
    .arg(
        Arg::new("PLUGIN_MODE")
            .long("plugin-mode")
            .num_args(1)
            .action(ArgAction::Set)
            .requires("PLUGIN")
            .help("SIP003/SIP003u plugin mode, must be one of `tcp_only` (default), `udp_only` and `tcp_and_udp`"),
    )
    .arg(
        Arg::new("PLUGIN_OPT")
            .long("plugin-opts")
            .num_args(1)
            .action(ArgAction::Set)
            .requires("PLUGIN")
            .help("Set SIP003 plugin options"),
    )
    .arg(
        Arg::new("SERVER_URL")
            .long("server-url")
            .num_args(1)
            .action(ArgAction::Set)
            .value_hint(ValueHint::Url)
            .value_parser(vparser::parse_server_url)
            .help("Server address in SIP002 (https://shadowsocks.org/doc/sip002.html) URL"),
    )
    .group(ArgGroup::new("SERVER_CONFIG")
        .arg("SERVER_ADDR").arg("SERVER_URL").multiple(true))
    .arg(
        Arg::new("ACL")
            .long("acl")
            .num_args(1)
            .action(ArgAction::Set)
            .value_hint(ValueHint::FilePath)
            .help("Path to ACL (Access Control List)"),
    )
    .arg(Arg::new("DNS").long("dns").num_args(1).action(ArgAction::Set).help("DNS nameservers, formatted like [(tcp|udp)://]host[:port][,host[:port]]..., or unix:///path/to/dns, or predefined keys like \"google\", \"cloudflare\""))
    .arg(Arg::new("DNS_CACHE_SIZE").long("dns-cache-size").num_args(1).action(ArgAction::Set).value_parser(clap::value_parser!(usize)).help("DNS cache size in number of records. Works when trust-dns DNS backend is enabled."))
    .arg(Arg::new("TCP_NO_DELAY").long("tcp-no-delay").alias("no-delay").action(ArgAction::SetTrue).help("Set TCP_NODELAY option for sockets"))
    .arg(Arg::new("TCP_FAST_OPEN").long("tcp-fast-open").alias("fast-open").action(ArgAction::SetTrue).help("Enable TCP Fast Open (TFO)"))
    .arg(Arg::new("TCP_KEEP_ALIVE").long("tcp-keep-alive").num_args(1).action(ArgAction::Set).value_parser(clap::value_parser!(u64)).help("Set TCP keep alive timeout seconds"))
    .arg(Arg::new("TCP_MULTIPATH").long("tcp-multipath").alias("mptcp").action(ArgAction::SetTrue).help("Enable Multipath-TCP (MPTCP)"))
    .arg(Arg::new("UDP_TIMEOUT").long("udp-timeout").num_args(1).action(ArgAction::Set).value_parser(clap::value_parser!(u64)).help("Timeout seconds for UDP relay"))
    .arg(Arg::new("UDP_MAX_ASSOCIATIONS").long("udp-max-associations").num_args(1).action(ArgAction::Set).value_parser(clap::value_parser!(usize)).help("Maximum associations to be kept simultaneously for UDP relay"))
    .arg(Arg::new("INBOUND_SEND_BUFFER_SIZE").long("inbound-send-buffer-size").num_args(1).action(ArgAction::Set).value_parser(clap::value_parser!(u32)).help("Set inbound sockets' SO_SNDBUF option"))
    .arg(Arg::new("INBOUND_RECV_BUFFER_SIZE").long("inbound-recv-buffer-size").num_args(1).action(ArgAction::Set).value_parser(clap::value_parser!(u32)).help("Set inbound sockets' SO_RCVBUF option"))
    .arg(Arg::new("OUTBOUND_SEND_BUFFER_SIZE").long("outbound-send-buffer-size").num_args(1).action(ArgAction::Set).value_parser(clap::value_parser!(u32)).help("Set outbound sockets' SO_SNDBUF option"))
    .arg(Arg::new("OUTBOUND_RECV_BUFFER_SIZE").long("outbound-recv-buffer-size").num_args(1).action(ArgAction::Set).value_parser(clap::value_parser!(u32)).help("Set outbound sockets' SO_RCVBUF option"))
    .arg(Arg::new("OUTBOUND_BIND_ADDR").long("outbound-bind-addr").num_args(1).alias("bind-addr").action(ArgAction::Set).value_parser(vparser::parse_ip_addr).help("Bind address, outbound socket will bind this address"))
    .arg(Arg::new("OUTBOUND_BIND_INTERFACE").long("outbound-bind-interface").num_args(1).action(ArgAction::Set).help("Set SO_BINDTODEVICE / IP_BOUND_IF / IP_UNICAST_IF option for outbound socket"))
    .arg(
        Arg::new("IPV6_FIRST")
            .short('6')
            .action(ArgAction::SetTrue)
            .help("Resolve hostname to IPv6 address first"),
    );

    #[cfg(feature = "logging")]
    {
        app = app
            .arg(
                Arg::new("VERBOSE")
                    .short('v')
                    .action(ArgAction::Count)
                    .help("Set log level"),
            )
            .arg(
                Arg::new("LOG_WITHOUT_TIME")
                    .long("log-without-time")
                    .action(ArgAction::SetTrue)
                    .help("Log without datetime prefix"),
            )
            .arg(
                Arg::new("LOG_CONFIG")
                    .long("log-config")
                    .num_args(1)
                    .action(ArgAction::Set)
                    .value_parser(clap::value_parser!(PathBuf))
                    .value_hint(ValueHint::FilePath)
                    .help("log4rs configuration file"),
            );
    }

    #[cfg(feature = "local-tunnel")]
    {
        app = app.arg(
            Arg::new("FORWARD_ADDR")
                .short('f')
                .long("forward-addr")
                .num_args(1)
                .action(ArgAction::Set)
                .requires("LOCAL_ADDR")
                .value_parser(vparser::parse_address)
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
                .num_args(1)
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(u64))
                .help("Set RLIMIT_NOFILE with both soft and hard limit"),
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        app = app.arg(
            Arg::new("OUTBOUND_FWMARK")
                .long("outbound-fwmark")
                .num_args(1)
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(u32))
                .help("Set SO_MARK option for outbound sockets"),
        );
    }

    #[cfg(target_os = "freebsd")]
    {
        app = app.arg(
            Arg::new("OUTBOUND_USER_COOKIE")
                .long("outbound-user-cookie")
                .num_args(1)
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(u32))
                .help("Set SO_USER_COOKIE option for outbound sockets"),
        );
    }

    #[cfg(feature = "local-redir")]
    {
        if RedirType::tcp_default() != RedirType::NotSupported {
            app = app.arg(
                Arg::new("TCP_REDIR")
                    .long("tcp-redir")
                    .num_args(1)
                    .action(ArgAction::Set)
                    .requires("LOCAL_ADDR")
                    .value_parser(PossibleValuesParser::new(RedirType::tcp_available_types()))
                    .help("TCP redir (transparent proxy) type"),
            );
        }

        if RedirType::udp_default() != RedirType::NotSupported {
            app = app.arg(
                Arg::new("UDP_REDIR")
                    .long("udp-redir")
                    .num_args(1)
                    .action(ArgAction::Set)
                    .requires("LOCAL_ADDR")
                    .value_parser(PossibleValuesParser::new(RedirType::udp_available_types()))
                    .help("UDP redir (transparent proxy) type"),
            );
        }
    }

    #[cfg(target_os = "android")]
    {
        app = app.arg(
            Arg::new("VPN_MODE")
                .long("vpn")
                .action(ArgAction::SetTrue)
                .help("Enable VPN mode (only for Android)"),
        );
    }

    #[cfg(feature = "local-flow-stat")]
    {
        #[cfg(unix)]
        {
            app = app.arg(
                Arg::new("STAT_PATH")
                    .long("stat-path")
                    .num_args(1)
                    .action(ArgAction::Set)
                    .value_hint(ValueHint::FilePath)
                    .conflicts_with("STAT_ADDR")
                    .help("Specify socket path (unix domain socket) for sending traffic statistic"),
            );
        }

        app = app.arg(
            Arg::new("STAT_ADDR")
                .long("stat-addr")
                .num_args(1)
                .action(ArgAction::Set)
                .value_parser(vparser::parse_socket_addr)
                .help("Specify socket address IP:PORT (TCP) for sending traffic statistic"),
        );
    }

    #[cfg(feature = "local-dns")]
    {
        app = app
            .arg(
                Arg::new("LOCAL_DNS_ADDR")
                    .long("local-dns-addr")
                    .num_args(1)
                    .action(ArgAction::Set)
                    .required_if_eq("PROTOCOL", "dns")
                    .requires("LOCAL_ADDR")
                    .value_parser(vparser::parse_name_server_addr)
                    .help("Specify the address of local DNS server, send queries directly"),
            )
            .arg(
                Arg::new("REMOTE_DNS_ADDR")
                    .long("remote-dns-addr")
                    .num_args(1)
                    .action(ArgAction::Set)
                    .required_if_eq("PROTOCOL", "dns")
                    .requires("LOCAL_ADDR")
                    .value_parser(self::local_value_parser::parse_remote_dns_address)
                    .help("Specify the address of remote DNS server, send queries through shadowsocks' tunnel"),
            );

        #[cfg(target_os = "android")]
        {
            app = app.arg(
                Arg::new("DNS_LOCAL_ADDR")
                    .long("dns-addr")
                    .num_args(1)
                    .action(ArgAction::Set)
                    .requires_all(&["LOCAL_ADDR", "REMOTE_DNS_ADDR"])
                    .value_parser(vparser::parse_server_addr)
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
                    .num_args(1)
                    .action(ArgAction::Set)
                    .help("Tun interface name, allocate one if not specify"),
            )
            .arg(
                Arg::new("TUN_INTERFACE_ADDRESS")
                    .long("tun-interface-address")
                    .num_args(1)
                    .action(ArgAction::Set)
                    .value_parser(vparser::parse_ipnet)
                    .help("Tun interface address (network)"),
            )
            .arg(
                Arg::new("TUN_INTERFACE_DESTINATION")
                    .long("tun-interface-destination")
                    .num_args(1)
                    .action(ArgAction::Set)
                    .value_parser(vparser::parse_ipnet)
                    .help("Tun interface destination address (network)"),
            );

        #[cfg(unix)]
        {
            app = app.arg(
                Arg::new("TUN_DEVICE_FD_FROM_PATH")
                    .long("tun-device-fd-from-path")
                    .num_args(1)
                    .action(ArgAction::Set)
                    .value_parser(clap::value_parser!(PathBuf))
                    .value_hint(ValueHint::AnyPath)
                    .help("Tun device file descriptor will be transferred from this unix domain socket path"),
            );
        }
    }

    #[cfg(feature = "local-fake-dns")]
    {
        app = app
            .arg(
                Arg::new("FAKE_DNS_RECORD_EXPIRE_DURATION")
                    .long("fake-dns-record-expire-duration")
                    .num_args(1)
                    .action(ArgAction::Set)
                    .value_parser(clap::value_parser!(u64))
                    .help("Fake DNS record expire duration in seconds"),
            )
            .arg(
                Arg::new("FAKE_DNS_IPV4_NETWORK")
                    .long("fake-dns-ipv4-network")
                    .num_args(1)
                    .action(ArgAction::Set)
                    .value_parser(vparser::parse_ipnet)
                    .help("Fake DNS IPv4 address network"),
            )
            .arg(
                Arg::new("FAKE_DNS_IPV6_NETWORK")
                    .long("fake-dns-ipv6-network")
                    .num_args(1)
                    .action(ArgAction::Set)
                    .value_parser(vparser::parse_ipnet)
                    .help("Fake DNS IPv6 address network"),
            )
            .arg(
                Arg::new("FAKE_DNS_DATABASE_PATH")
                    .long("fake-dns-database-path")
                    .num_args(1)
                    .action(ArgAction::Set)
                    .value_hint(ValueHint::AnyPath)
                    .help("Fake DNS database storage path"),
            );
    }

    #[cfg(unix)]
    {
        app = app
            .arg(
                Arg::new("DAEMONIZE")
                    .short('d')
                    .long("daemonize")
                    .action(ArgAction::SetTrue)
                    .help("Daemonize"),
            )
            .arg(
                Arg::new("DAEMONIZE_PID_PATH")
                    .long("daemonize-pid")
                    .num_args(1)
                    .action(ArgAction::Set)
                    .value_parser(clap::value_parser!(PathBuf))
                    .value_hint(ValueHint::FilePath)
                    .help("File path to store daemonized process's PID"),
            );
    }

    #[cfg(feature = "multi-threaded")]
    {
        app = app
            .arg(
                Arg::new("SINGLE_THREADED")
                    .long("single-threaded")
                    .action(ArgAction::SetTrue)
                    .help("Run the program all in one thread"),
            )
            .arg(
                Arg::new("WORKER_THREADS")
                    .long("worker-threads")
                    .num_args(1)
                    .action(ArgAction::Set)
                    .value_parser(clap::value_parser!(usize))
                    .help("Sets the number of worker threads the `Runtime` will use"),
            );
    }

    #[cfg(unix)]
    {
        app = app.arg(
            Arg::new("USER")
                .long("user")
                .short('a')
                .num_args(1)
                .action(ArgAction::Set)
                .value_hint(ValueHint::Username)
                .help("Run as another user"),
        );
    }

    #[cfg(feature = "local-online-config")]
    {
        app = app
            .arg(
                Arg::new("ONLINE_CONFIG_URL")
                    .long("online-config-url")
                    .num_args(1)
                    .action(ArgAction::Set)
                    .value_hint(ValueHint::Url)
                    .help("SIP008 Online Configuration Delivery URL (https://shadowsocks.org/doc/sip008.html)"),
            )
            .arg(
                Arg::new("ONLINE_CONFIG_UPDATE_INTERVAL")
                    .long("online-config-update-interval")
                    .num_args(1)
                    .action(ArgAction::Set)
                    .value_parser(clap::value_parser!(u64))
                    .help("SIP008 Online Configuration Delivery update interval in seconds, 3600 by default"),
            )
            .arg(
                Arg::new("ONLINE_CONFIG_ALLOWED_PLUGIN")
                    .long("online-config-allowed-plugin")
                    .action(ArgAction::Append)
                    .help("SIP008 Online Configuration Delivery allowed plugin list"),
            );
    }

    app
}

/// Create `Runtime` and `main` entry
pub fn create(matches: &ArgMatches) -> ShadowsocksResult<(Runtime, impl Future<Output = ShadowsocksResult> + use<>)> {
    #[cfg_attr(not(feature = "local-online-config"), allow(unused_mut))]
    let (config, _, runtime) = {
        let config_path_opt = matches.get_one::<PathBuf>("CONFIG").cloned().or_else(|| {
            if !matches.contains_id("SERVER_CONFIG") {
                match crate::config::get_default_config_path("local.json") {
                    None => None,
                    Some(p) => {
                        println!("loading default config {p:?}");
                        Some(p)
                    }
                }
            } else {
                None
            }
        });

        let mut service_config = match config_path_opt {
            Some(ref config_path) => ServiceConfig::load_from_file(config_path)
                .map_err(|err| ShadowsocksError::LoadConfigFailure(format!("loading config {config_path:?}, {err}")))?,
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
            Some(cpath) => Config::load_from_file(&cpath, ConfigType::Local)
                .map_err(|err| ShadowsocksError::LoadConfigFailure(format!("loading config {cpath:?}, {err}")))?,
            None => Config::new(ConfigType::Local),
        };

        if let Some(svr_addr) = matches.get_one::<String>("SERVER_ADDR") {
            let method = matches
                .get_one::<String>("ENCRYPT_METHOD")
                .map(|x| x.parse::<CipherKind>().expect("method"))
                .expect("`method` is required");

            let password = match matches.get_one::<String>("PASSWORD") {
                Some(pwd) => read_variable_field_value(pwd).into(),
                None => {
                    // NOTE: svr_addr should have been checked by crate::vparser
                    if method.is_none() {
                        // If method doesn't need a key (none, plain), then we can leave it empty
                        String::new()
                    } else {
                        match crate::password::read_server_password(svr_addr) {
                            Ok(pwd) => pwd,
                            Err(..) => panic!("`password` is required for server {svr_addr}"),
                        }
                    }
                }
            };

            let svr_addr = svr_addr.parse::<ServerAddr>().expect("server-addr");
            let timeout = matches.get_one::<u64>("TIMEOUT").map(|x| Duration::from_secs(*x));

            let mut sc = match ServerConfig::new(svr_addr, password, method) {
                Ok(sc) => sc,
                Err(err) => {
                    panic!("failed to create ServerConfig, error: {}", err);
                }
            };
            sc.set_source(ServerSource::CommandLine);
            if let Some(timeout) = timeout {
                sc.set_timeout(timeout);
            }

            if let Some(p) = matches.get_one::<String>("PLUGIN").cloned() {
                let plugin = PluginConfig {
                    plugin: p,
                    plugin_opts: matches.get_one::<String>("PLUGIN_OPT").cloned(),
                    plugin_args: Vec::new(),
                    plugin_mode: matches
                        .get_one::<String>("PLUGIN_MODE")
                        .map(|x| {
                            x.parse::<Mode>()
                                .expect("plugin-mode must be one of `tcp_only` (default), `udp_only` and `tcp_and_udp`")
                        })
                        .unwrap_or(Mode::TcpOnly),
                };

                sc.set_plugin(plugin);
            }

            config.server.push(ServerInstanceConfig::with_server_config(sc));
        }

        if let Some(mut svr_addr) = matches.get_one::<ServerConfig>("SERVER_URL").cloned() {
            svr_addr.set_source(ServerSource::CommandLine);
            config.server.push(ServerInstanceConfig::with_server_config(svr_addr));
        }

        #[cfg(feature = "local-flow-stat")]
        {
            use shadowsocks_service::config::LocalFlowStatAddress;
            use std::net::SocketAddr;

            #[cfg(unix)]
            if let Some(stat_path) = matches.get_one::<String>("STAT_PATH") {
                config.local_stat_addr = Some(LocalFlowStatAddress::UnixStreamPath(From::from(stat_path)));
            }

            if let Some(stat_addr) = matches.get_one::<SocketAddr>("STAT_ADDR").cloned() {
                config.local_stat_addr = Some(LocalFlowStatAddress::TcpStreamAddr(stat_addr));
            }
        }

        #[cfg(target_os = "android")]
        if matches.get_flag("VPN_MODE") {
            // A socket `protect_path` in CWD
            // Same as shadowsocks-libev's android.c
            config.outbound_vpn_protect_path = Some(From::from("protect_path"));
        }

        if matches.get_raw("LOCAL_ADDR").is_some() || matches.get_raw("PROTOCOL").is_some() {
            let protocol = match matches.get_one::<String>("PROTOCOL").map(|s| s.as_str()) {
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
                Some(p) => panic!("not supported `protocol` \"{p}\""),
                None => ProtocolType::Socks,
            };

            let mut local_config = LocalConfig::new(protocol);
            match matches.get_one::<ServerAddr>("LOCAL_ADDR").cloned() {
                Some(local_addr) => local_config.addr = Some(local_addr),
                None => {
                    #[cfg(feature = "local-tun")]
                    if protocol == ProtocolType::Tun {
                        // `tun` protocol doesn't need --local-addr
                    } else {
                        panic!("`local-addr` is required for protocol {}", protocol.as_str());
                    }
                }
            }

            if let Some(udp_bind_addr) = matches.get_one::<ServerAddr>("UDP_BIND_ADDR").cloned() {
                local_config.udp_addr = Some(udp_bind_addr);
            }

            if let Some(udp_associate_addr) = matches.get_one::<ServerAddr>("UDP_ASSOCIATE_ADDR").cloned() {
                local_config.udp_associate_addr = Some(udp_associate_addr);
            }

            #[cfg(feature = "local-tunnel")]
            if let Some(addr) = matches.get_one::<Address>("FORWARD_ADDR").cloned() {
                local_config.forward_addr = Some(addr);
            }

            #[cfg(feature = "local-redir")]
            {
                if RedirType::tcp_default() != RedirType::NotSupported {
                    if let Some(tcp_redir) = matches.get_one::<String>("TCP_REDIR") {
                        local_config.tcp_redir = tcp_redir.parse::<RedirType>().expect("tcp-redir");
                    }
                }

                if RedirType::udp_default() != RedirType::NotSupported {
                    if let Some(udp_redir) = matches.get_one::<String>("UDP_REDIR") {
                        local_config.udp_redir = udp_redir.parse::<RedirType>().expect("udp-redir");
                    }
                }
            }

            #[cfg(feature = "local-dns")]
            {
                use shadowsocks_service::local::dns::NameServerAddr;

                use self::local_value_parser::RemoteDnsAddress;

                if let Some(addr) = matches.get_one::<NameServerAddr>("LOCAL_DNS_ADDR").cloned() {
                    local_config.local_dns_addr = Some(addr);
                }

                if let Some(addr) = matches.get_one::<RemoteDnsAddress>("REMOTE_DNS_ADDR").cloned() {
                    local_config.remote_dns_addr = Some(addr.0);
                }
            }

            #[cfg(all(feature = "local-dns", target_os = "android"))]
            if protocol != ProtocolType::Dns {
                // Start a DNS local server binding to DNS_LOCAL_ADDR
                //
                // This is a special route only for shadowsocks-android
                if let Some(addr) = matches.get_one::<ServerAddr>("DNS_LOCAL_ADDR").cloned() {
                    let mut local_dns_config = LocalConfig::new_with_addr(addr, ProtocolType::Dns);

                    // The `local_dns_addr` and `remote_dns_addr` are for this DNS server (for compatibility)
                    local_dns_config.local_dns_addr = local_config.local_dns_addr.take();
                    local_dns_config.remote_dns_addr = local_config.remote_dns_addr.take();

                    config
                        .local
                        .push(LocalInstanceConfig::with_local_config(local_dns_config));
                }
            }

            #[cfg(feature = "local-tun")]
            {
                use ipnet::IpNet;

                if let Some(tun_address) = matches.get_one::<IpNet>("TUN_INTERFACE_ADDRESS").cloned() {
                    local_config.tun_interface_address = Some(tun_address);
                }
                if let Some(tun_address) = matches.get_one::<IpNet>("TUN_INTERFACE_DESTINATION").cloned() {
                    local_config.tun_interface_destination = Some(tun_address);
                }
                if let Some(tun_name) = matches.get_one::<String>("TUN_INTERFACE_NAME").cloned() {
                    local_config.tun_interface_name = Some(tun_name);
                }

                #[cfg(unix)]
                if let Some(fd_path) = matches.get_one::<PathBuf>("TUN_DEVICE_FD_FROM_PATH").cloned() {
                    local_config.tun_device_fd_from_path = Some(fd_path);
                }
            }

            #[cfg(feature = "local-fake-dns")]
            {
                use ipnet::{Ipv4Net, Ipv6Net};

                if let Some(d) = matches.get_one::<u64>("FAKE_DNS_RECORD_EXPIRE_DURATION") {
                    local_config.fake_dns_record_expire_duration = Some(Duration::from_secs(*d));
                }
                if let Some(n) = matches.get_one::<Ipv4Net>("FAKE_DNS_IPV4_NETWORK") {
                    local_config.fake_dns_ipv4_network = Some(*n);
                }
                if let Some(n) = matches.get_one::<Ipv6Net>("FAKE_DNS_IPV6_NETWORK") {
                    local_config.fake_dns_ipv6_network = Some(*n);
                }
                if let Some(p) = matches.get_one::<PathBuf>("FAKE_DNS_DATABASE_PATH").cloned() {
                    local_config.fake_dns_database_path = Some(p);
                }
            }

            if matches.get_flag("UDP_ONLY") {
                local_config.mode = Mode::UdpOnly;
            }

            if matches.get_flag("TCP_AND_UDP") {
                local_config.mode = Mode::TcpAndUdp;
            }

            config.local.push(LocalInstanceConfig::with_local_config(local_config));
        }

        if matches.get_flag("TCP_NO_DELAY") {
            config.no_delay = true;
        }

        if matches.get_flag("TCP_FAST_OPEN") {
            config.fast_open = true;
        }

        if let Some(keep_alive) = matches.get_one::<u64>("TCP_KEEP_ALIVE") {
            config.keep_alive = Some(Duration::from_secs(*keep_alive));
        }

        if matches.get_flag("TCP_MULTIPATH") {
            config.mptcp = true;
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(mark) = matches.get_one::<u32>("OUTBOUND_FWMARK") {
            config.outbound_fwmark = Some(*mark);
        }

        #[cfg(target_os = "freebsd")]
        if let Some(user_cookie) = matches.get_one::<u32>("OUTBOUND_USER_COOKIE") {
            config.outbound_user_cookie = Some(*user_cookie);
        }

        if let Some(iface) = matches.get_one::<String>("OUTBOUND_BIND_INTERFACE").cloned() {
            config.outbound_bind_interface = Some(iface);
        }

        #[cfg(all(unix, not(target_os = "android")))]
        match matches.get_one::<u64>("NOFILE") {
            Some(nofile) => config.nofile = Some(*nofile),
            None => {
                if config.nofile.is_none() {
                    crate::sys::adjust_nofile();
                }
            }
        }

        if let Some(acl_file) = matches.get_one::<String>("ACL") {
            let acl = AccessControl::load_from_file(acl_file)
                .map_err(|err| ShadowsocksError::LoadAclFailure(format!("loading ACL \"{acl_file}\", {err}")))?;
            config.acl = Some(acl);
        }

        if let Some(dns) = matches.get_one::<String>("DNS") {
            config.set_dns_formatted(dns).expect("dns");
        }

        if let Some(dns_cache_size) = matches.get_one::<usize>("DNS_CACHE_SIZE") {
            config.dns_cache_size = Some(*dns_cache_size);
        }

        if matches.get_flag("IPV6_FIRST") {
            config.ipv6_first = true;
        }

        if let Some(udp_timeout) = matches.get_one::<u64>("UDP_TIMEOUT") {
            config.udp_timeout = Some(Duration::from_secs(*udp_timeout));
        }

        if let Some(udp_max_assoc) = matches.get_one::<usize>("UDP_MAX_ASSOCIATIONS") {
            config.udp_max_associations = Some(*udp_max_assoc);
        }

        if let Some(bs) = matches.get_one::<u32>("INBOUND_SEND_BUFFER_SIZE") {
            config.inbound_send_buffer_size = Some(*bs);
        }
        if let Some(bs) = matches.get_one::<u32>("INBOUND_RECV_BUFFER_SIZE") {
            config.inbound_recv_buffer_size = Some(*bs);
        }
        if let Some(bs) = matches.get_one::<u32>("OUTBOUND_SEND_BUFFER_SIZE") {
            config.outbound_send_buffer_size = Some(*bs);
        }
        if let Some(bs) = matches.get_one::<u32>("OUTBOUND_RECV_BUFFER_SIZE") {
            config.outbound_recv_buffer_size = Some(*bs);
        }

        if let Some(bind_addr) = matches.get_one::<IpAddr>("OUTBOUND_BIND_ADDR") {
            config.outbound_bind_addr = Some(*bind_addr);
        }

        #[cfg(feature = "local-online-config")]
        if let Some(online_config_url) = matches.get_one::<String>("ONLINE_CONFIG_URL") {
            use shadowsocks_service::config::OnlineConfig;

            let online_config_update_interval = matches.get_one::<u64>("ONLINE_CONFIG_UPDATE_INTERVAL").cloned();

            let mut allowed_plugins = None;
            if let Some(plugins) = matches.get_many::<String>("ONLINE_CONFIG_ALLOWED_PLUGIN") {
                allowed_plugins = Some(plugins.cloned().collect());
            }

            config.online_config = Some(OnlineConfig {
                config_url: online_config_url.clone(),
                update_interval: online_config_update_interval.map(Duration::from_secs),
                allowed_plugins,
            });
        }

        // DONE READING options

        if config.local.is_empty() {
            return Err(ShadowsocksError::InsufficientParams(
                "missing `local_address`, consider specifying it by --local-addr command line option, \
                    or \"local_address\" and \"local_port\" in configuration file"
                    .to_string(),
            ));
        }

        config
            .check_integrity()
            .map_err(|err| ShadowsocksError::LoadConfigFailure(format!("config integrity check failed, {err}")))?;

        #[cfg(unix)]
        if matches.get_flag("DAEMONIZE") || matches.get_raw("DAEMONIZE_PID_PATH").is_some() {
            use crate::daemonize;
            daemonize::daemonize(matches.get_one::<PathBuf>("DAEMONIZE_PID_PATH"));
        }

        #[cfg(unix)]
        if let Some(uname) = matches.get_one::<String>("USER") {
            crate::sys::run_as_user(uname).map_err(|err| {
                ShadowsocksError::InsufficientParams(format!("failed to change as user, error: {err}"))
            })?;
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

        (config, service_config, runtime)
    };

    let main_fut = async move {
        let config_path = config.config_path.clone();

        let instance = Server::new(config).await.expect("create local");

        let reload_task = match config_path {
            Some(config_path) => ServerReloader {
                config_path: config_path.clone(),
                balancer: instance.server_balancer().clone(),
            }
            .launch_reload_server_task()
            .boxed(),
            None => future::pending().boxed(),
        };

        let abort_signal = monitor::create_signal_monitor();
        let server = instance.run();

        let reload_task = reload_task.fuse();
        let abort_signal = abort_signal.fuse();
        let server = server.fuse();

        tokio::pin!(reload_task);
        tokio::pin!(abort_signal);
        tokio::pin!(server);

        loop {
            futures::select! {
                server_res = server => {
                    match server_res {
                        // Server future resolved without an error. This should never happen.
                        Ok(..) => {
                            return Err(ShadowsocksError::ServerExitUnexpectedly("server exited unexpectedly".to_owned()));
                        }
                        // Server future resolved with error, which are listener errors in most cases
                        Err(err) => {
                            return Err(ShadowsocksError::ServerAborted(format!("server aborted with {err}")));
                        }
                    }
                }
                // The abort signal future resolved. Means we should just exit.
                _ = abort_signal => {
                    return Ok(());
                }
                _ = reload_task => {
                    // continue.
                    trace!("server-loader task task exited");
                }
            }
        }
    };

    Ok((runtime, main_fut))
}

/// Program entrance `main`
#[inline]
pub fn main(matches: &ArgMatches) -> ExitCode {
    match create(matches).and_then(|(runtime, main_fut)| runtime.block_on(main_fut)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            err.exit_code().into()
        }
    }
}

struct ServerReloader {
    config_path: PathBuf,
    balancer: PingBalancer,
}

impl ServerReloader {
    #[cfg_attr(not(unix), allow(dead_code))]
    async fn run_once(&self) -> Result<(), Box<dyn std::error::Error>> {
        let start_time = Instant::now();

        // Load servers from source
        let source_config = match Config::load_from_file(&self.config_path, ConfigType::Local) {
            Ok(c) => c,
            Err(err) => {
                error!(
                    "server-loader task failed to load from file: {}, error: {}",
                    self.config_path.display(),
                    err
                );
                return Err(Box::new(err));
            }
        };

        let server_len = source_config.server.len();

        let fetch_end_time = Instant::now();

        if let Err(err) = self
            .balancer
            .reset_servers(source_config.server, &[ServerSource::Configuration])
            .await
        {
            error!("server-loader task {} servers but found error: {}", server_len, err);
            return Err(Box::new(err));
        }

        let total_end_time = Instant::now();

        info!(
            "server-loader task load from {} with {} servers, fetch costs: {:?}, total costs: {:?}",
            self.config_path.display(),
            server_len,
            fetch_end_time - start_time,
            total_end_time - start_time,
        );

        Ok(())
    }

    #[cfg(unix)]
    async fn launch_signal_reload_server_task(self: Arc<Self>) {
        use log::debug;
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigusr1 = signal(SignalKind::user_defined1()).expect("signal");

        debug!("server-loader task is now listening USR1");

        while sigusr1.recv().await.is_some() {
            let _ = self.run_once().await;
        }
    }

    #[cfg(unix)]
    async fn launch_reload_server_task(self) {
        let arc_self = Arc::new(self);
        arc_self.launch_signal_reload_server_task().await
    }

    #[cfg(windows)]
    async fn launch_reload_server_task(self) {
        let _ = self.config_path;
        let _ = self.balancer;
    }
}

#[cfg(test)]
mod test {
    use clap::Command;

    #[test]
    fn verify_local_command() {
        let mut app = Command::new("shadowsocks")
            .version(crate::VERSION)
            .about("A fast tunnel proxy that helps you bypass firewalls. (https://shadowsocks.org)");
        app = super::define_command_line_options(app);
        app.debug_assert();
    }
}
