//! This is a binary running in the local environment
//!
//! You have to provide all needed configuration attributes via command line parameters,
//! or you could specify a configuration file. The format of configuration file is defined
//! in mod `config`.

use std::time::Duration;

use clap::{clap_app, Arg};
use futures::future::{self, Either};
use log::info;
use tokio::{self, runtime::Builder};

#[cfg(feature = "local-redir")]
use shadowsocks::config::RedirType;
#[cfg(any(feature = "local-dns", feature = "local-tunnel"))]
use shadowsocks::relay::socks5::Address;
use shadowsocks::{
    acl::AccessControl,
    crypto::v1::{available_ciphers, CipherKind},
    plugin::PluginConfig,
    run_local,
    Config,
    ConfigType,
    Mode,
    ServerAddr,
    ServerConfig,
};

mod allocator;
#[cfg(unix)]
mod daemonize;
mod logging;
mod monitor;
mod validator;
mod version;

const AVAILABLE_PROTOCOLS: &[&str] = &[
    "socks5",
    #[cfg(feature = "local-socks4")]
    "socks4",
    #[cfg(feature = "local-http")]
    "http",
    #[cfg(all(
        feature = "local-http",
        any(feature = "local-http-native-tls", feature = "local-http-rustls")
    ))]
    "https",
    #[cfg(feature = "local-tunnel")]
    "tunnel",
    #[cfg(feature = "local-redir")]
    "redir",
    #[cfg(feature = "local-dns")]
    "dns",
];

fn main() {
    let mut app = clap_app!(shadowsocks =>
        (version: self::version::VERSION)
        (about: "A fast tunnel proxy that helps you bypass firewalls.")
        (@arg VERBOSE: -v ... "Set the level of debug")
        (@arg UDP_ONLY: -u conflicts_with[TCP_AND_UDP] "Server mode UDP_ONLY")
        (@arg TCP_AND_UDP: -U "Server mode TCP_AND_UDP")

        (@arg CONFIG: -c --config +takes_value required_unless_all(&["LOCAL_ADDR", "SERVER_CONFIG"]) "Shadowsocks configuration file (https://shadowsocks.org/en/config/quick-guide.html)")

        (@arg LOCAL_ADDR: -b --("local-addr") +takes_value {validator::validate_server_addr} "Local address, listen only to this address if specified")

        (@arg SERVER_ADDR: -s --("server-addr") +takes_value {validator::validate_server_addr} requires[PASSWORD ENCRYPT_METHOD] "Server address")
        (@arg PASSWORD: -k --password +takes_value requires[SERVER_ADDR] "Server's password")
        (@arg ENCRYPT_METHOD: -m --("encrypt-method") +takes_value requires[SERVER_ADDR] possible_values(available_ciphers()) +next_line_help "Server's encryption method")
        (@arg TIMEOUT: --timeout +takes_value {validator::validate_u64} requires[SERVER_ADDR] "Server's timeout seconds for TCP relay")

        (@arg PLUGIN: --plugin +takes_value requires[SERVER_ADDR] "SIP003 (https://shadowsocks.org/en/spec/Plugin.html) plugin")
        (@arg PLUGIN_OPT: --("plugin-opts") +takes_value requires[PLUGIN] "Set SIP003 plugin options")

        (@arg URL: --("server-url") +takes_value {validator::validate_server_url} "Server address in SIP002 (https://shadowsocks.org/en/spec/SIP002-URI-Scheme.html) URL")

        (@group SERVER_CONFIG =>
            (@attributes +multiple arg[SERVER_ADDR URL]))

        (@arg PROTOCOL: --protocol +takes_value default_value("socks5") possible_values(AVAILABLE_PROTOCOLS) +next_line_help "Protocol that for communicating with clients")

        (@arg NO_DELAY: --("no-delay") !takes_value "Set TCP_NODELAY option for socket")
        (@arg NOFILE: -n --nofile +takes_value "Set RLIMIT_NOFILE with both soft and hard limit (only for *nix systems)")
        (@arg ACL: --acl +takes_value "Path to ACL (Access Control List)")

        (@arg LOG_WITHOUT_TIME: --("log-without-time") "Log without datetime prefix")
        (@arg LOG_CONFIG: --("log-config") +takes_value "log4rs configuration file")

        (@arg UDP_TIMEOUT: --("udp-timeout") +takes_value {validator::validate_u64} "Timeout seconds for UDP relay")
        (@arg UDP_MAX_ASSOCIATIONS: --("udp-max-associations") +takes_value {validator::validate_u64} "Maximum associations to be kept simultaneously for UDP relay")

        (@arg UDP_BIND_ADDR: --("udp-bind-addr") +takes_value {validator::validate_server_addr} "UDP relay's bind address, default is the same as local-addr")
    );

    // FIXME: -6 is not a identifier, so we cannot build it with clap_app!
    app = app.arg(
        Arg::with_name("IPV6_FIRST")
            .short("6")
            .help("Resolve hostname to IPv6 address first"),
    );

    #[cfg(feature = "local-tunnel")]
    {
        app = clap_app!(@app (app)
            (@arg FORWARD_ADDR: -f --("forward-addr") +takes_value {validator::validate_address} required_if("PROTOCOL", "tunnel") "Forwarding data directly to this address (for tunnel)")
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        app = clap_app!(@app (app)
            (@arg OUTBOUND_FWMARK: --("outbound-fwmark") +takes_value {validator::validate_u32} "Set SO_MARK option for outbound socket")
        );
    }

    #[cfg(feature = "local-redir")]
    {
        let available_redir_types = RedirType::available_types();

        if RedirType::tcp_default() != RedirType::NotSupported {
            app = clap_app!(@app (app)
                (@arg TCP_REDIR: --("tcp-redir") +takes_value possible_values(&available_redir_types) default_value(RedirType::tcp_default().name()) "TCP redir (transparent proxy) type")
            );
        }

        if RedirType::udp_default() != RedirType::NotSupported {
            app = clap_app!(@app (app)
                (@arg UDP_REDIR: --("udp-redir") +takes_value possible_values(&available_redir_types) default_value(RedirType::udp_default().name()) "UDP redir (transparent proxy) type")
            );
        }
    }

    #[cfg(target_os = "android")]
    {
        app = clap_app!(@app (app)
            (@arg VPN_MODE: --vpn "Enable VPN mode (only for Android)")
        );
    }

    #[cfg(feature = "local-flow-stat")]
    {
        app = clap_app!(@app (app)
            (@arg STAT_PATH: --("stat-path") +takes_value "Specify socket path (unix domain socket) for sending traffic statistic")
        );
    }

    #[cfg(feature = "local-dns")]
    {
        app = clap_app!(@app (app)
            (@arg LOCAL_DNS_ADDR: --("local-dns-addr") +takes_value required_if("PROTOCOL", "dns") {validator::validate_local_dns_addr} "Specify the address of local DNS server, send queries directly")
            (@arg REMOTE_DNS_ADDR: --("remote-dns-addr") +takes_value required_if("PROTOCOL", "dns") {validator::validate_address} "Specify the address of remote DNS server, send queries through shadowsocks' tunnel")
            (@arg DNS_LOCAL_ADDR: --("dns-addr") +takes_value requires_all(&["REMOTE_DNS_ADDR"]) {validator::validate_server_addr} "DNS address, listen to this address if specified")
        );
    }

    #[cfg(feature = "local-http-native-tls")]
    {
        app = clap_app!(@app (app)
            (@arg TLS_IDENTITY_PATH: --("tls-identity") +takes_value required_if("PROTOCOL", "https") requires[TLS_IDENTITY_PASSWORD] "TLS identity file (PKCS #12) path for HTTPS server")
            (@arg TLS_IDENTITY_PASSWORD: --("tls-identity-password") +takes_value required_if("PROTOCOL", "https") requires[TLS_IDENTITY_PATH] "TLS identity file's password for HTTPS server")
        );
    }

    #[cfg(feature = "local-http-rustls")]
    {
        app = clap_app!(@app (app)
            (@arg TLS_IDENTITY_CERT_PATH: --("tls-identity-certificate") +takes_value required_if("PROTOCOL", "https") requires[TLS_IDENTITY_PRIVATE_KEY_PATH] "TLS identity certificate (PEM) path for HTTPS server")
            (@arg TLS_IDENTITY_PRIVATE_KEY_PATH: --("tls-identity-private-key") +takes_value required_if("PROTOCOL", "https") requires[TLS_IDENTITY_CERT_PATH] "TLS identity private key (PEM), PKCS #8 or RSA syntax, for HTTPS server")
        );
    }

    #[cfg(unix)]
    {
        app = clap_app!(@app (app)
            (@arg DAEMONIZE: -d --("daemonize") "Daemonize")
            (@arg DAEMONIZE_PID_PATH: --("daemonize-pid") +takes_value "File path to store daemonized process's PID")
        );
    }

    let matches = app.get_matches();
    // drop(available_ciphers);

    match matches.value_of("LOG_CONFIG") {
        Some(path) => {
            logging::init_with_file(path);
        }
        None => {
            logging::init_with_config("sslocal", &matches);
        }
    }

    let config_type = match matches.value_of("PROTOCOL") {
        Some("socks5") => ConfigType::Socks5Local,
        #[cfg(feature = "local-socks4")]
        Some("socks4") => ConfigType::Socks4Local,
        #[cfg(feature = "local-http")]
        Some("http") => ConfigType::HttpLocal,
        #[cfg(all(
            feature = "local-http",
            any(feature = "local-http-native-tls", feature = "local-http-rustls")
        ))]
        Some("https") => ConfigType::HttpsLocal,
        #[cfg(feature = "local-tunnel")]
        Some("tunnel") => ConfigType::TunnelLocal,
        #[cfg(feature = "local-redir")]
        Some("redir") => ConfigType::RedirLocal,
        #[cfg(feature = "local-dns")]
        Some("dns") => ConfigType::DnsLocal,
        Some(p) => panic!("not supported `protocol` \"{}\"", p),
        None => ConfigType::Socks5Local,
    };

    let mut config = match matches.value_of("CONFIG") {
        Some(cpath) => match Config::load_from_file(cpath, config_type) {
            Ok(cfg) => cfg,
            Err(err) => {
                panic!("loading config \"{}\", {}", cpath, err);
            }
        },
        None => Config::new(config_type),
    };

    if let Some(svr_addr) = matches.value_of("SERVER_ADDR") {
        let password = matches.value_of("PASSWORD").expect("password");
        let method = matches
            .value_of("ENCRYPT_METHOD")
            .expect("encrypt-method")
            .parse::<CipherKind>()
            .expect("encryption method");
        let svr_addr = svr_addr.parse::<ServerAddr>().expect("server-addr");

        let timeout = matches
            .value_of("TIMEOUT")
            .map(|t| t.parse::<u64>().expect("timeout"))
            .map(Duration::from_secs);

        let mut sc = ServerConfig::new(svr_addr, password.to_owned(), method, timeout, None);

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

    if let Some(url) = matches.value_of("URL") {
        let svr_addr = url.parse::<ServerConfig>().expect("server SIP002 url");
        config.server.push(svr_addr);
    }

    #[cfg(feature = "local-flow-stat")]
    {
        if let Some(stat_path) = matches.value_of("STAT_PATH") {
            config.stat_path = Some(From::from(stat_path));
        }
    }

    #[cfg(feature = "local-dns")]
    {
        use shadowsocks::config::LocalDnsAddr;

        if let Some(local_dns_addr) = matches.value_of("LOCAL_DNS_ADDR") {
            let addr = local_dns_addr.parse::<LocalDnsAddr>().expect("local dns address");
            config.local_dns_addr = Some(addr);
        }

        if let Some(remote_dns_addr) = matches.value_of("REMOTE_DNS_ADDR") {
            let addr = remote_dns_addr.parse::<Address>().expect("remote dns address");
            config.remote_dns_addr = Some(addr);
        }

        if let Some(dns_relay_addr) = matches.value_of("DNS_LOCAL_ADDR") {
            let addr = dns_relay_addr.parse::<ServerAddr>().expect("dns relay address");
            config.dns_bind_addr = Some(addr);
        }
    }

    #[cfg(target_os = "android")]
    if matches.is_present("VPN_MODE") {
        // A socket `protect_path` in CWD
        // Same as shadowsocks-libev's android.c
        config.protect_path = Some(From::from("protect_path"));

        // Set default config.local_dns_addr
        #[cfg(feature = "local-dns")]
        if config.local_dns_addr.is_none() {
            config.local_dns_addr = Some(From::from("local_dns_path"));
        }
    }

    if let Some(local_addr) = matches.value_of("LOCAL_ADDR") {
        let local_addr = local_addr.parse::<ServerAddr>().expect("local bind addr");
        config.local_addr = Some(local_addr);
    }

    // override the config's mode if UDP_ONLY is set
    if matches.is_present("UDP_ONLY") {
        config.mode = Mode::UdpOnly;
    }

    if matches.is_present("TCP_AND_UDP") {
        config.mode = Mode::TcpAndUdp;
    }

    if matches.is_present("NO_DELAY") {
        config.no_delay = true;
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some(mark) = matches.value_of("OUTBOUND_FWMARK") {
        config.outbound_fwmark = Some(mark.parse::<u32>().expect("an unsigned integer for `outbound-fwmark`"));
    }

    if let Some(nofile) = matches.value_of("NOFILE") {
        config.nofile = Some(nofile.parse::<u64>().expect("an unsigned integer for `nofile`"));
    }

    if let Some(acl_file) = matches.value_of("ACL") {
        let acl = match AccessControl::load_from_file(acl_file) {
            Ok(acl) => acl,
            Err(err) => {
                panic!("loading ACL \"{}\", {}", acl_file, err);
            }
        };
        config.acl = Some(acl);
    }

    if matches.is_present("IPV6_FIRST") {
        config.ipv6_first = true;
    }

    #[cfg(feature = "local-tunnel")]
    if let Some(faddr) = matches.value_of("FORWARD_ADDR") {
        let addr = faddr.parse::<Address>().expect("forward-addr");
        config.forward = Some(addr);
    }

    #[cfg(feature = "local-redir")]
    {
        if let Some(tcp_redir) = matches.value_of("TCP_REDIR") {
            config.tcp_redir = tcp_redir.parse::<RedirType>().expect("TCP redir type");
        }

        if let Some(udp_redir) = matches.value_of("UDP_REDIR") {
            config.udp_redir = udp_redir.parse::<RedirType>().expect("UDP redir type");
        }
    }

    #[cfg(feature = "local-http-native-tls")]
    {
        if let Some(ipath) = matches.value_of("TLS_IDENTITY_PATH") {
            config.tls_identity_path = Some(ipath.into());
        }

        if let Some(ipwd) = matches.value_of("TLS_IDENTITY_PASSWORD") {
            config.tls_identity_password = Some(ipwd.into());
        }
    }

    #[cfg(feature = "local-http-rustls")]
    {
        if let Some(cpath) = matches.value_of("TLS_IDENTITY_CERT_PATH") {
            config.tls_identity_certificate_path = Some(cpath.into());
        }

        if let Some(kpath) = matches.value_of("TLS_IDENTITY_PRIVATE_KEY_PATH") {
            config.tls_identity_private_key_path = Some(kpath.into());
        }
    }

    if let Some(udp_timeout) = matches.value_of("UDP_TIMEOUT") {
        config.udp_timeout = Some(Duration::from_secs(udp_timeout.parse::<u64>().expect("udp-timeout")));
    }

    if let Some(udp_max_assoc) = matches.value_of("UDP_MAX_ASSOCIATIONS") {
        config.udp_max_associations = Some(udp_max_assoc.parse::<usize>().expect("udp-max-associations"));
    }

    if let Some(udp_bind_addr) = matches.value_of("UDP_BIND_ADDR") {
        config.udp_bind_addr = Some(udp_bind_addr.parse::<ServerAddr>().expect("udp-bind-addr"));
    }

    // DONE READING options

    if config.local_addr.is_none() {
        eprintln!(
            "missing `local_address`, consider specifying it by --local-addr command line option, \
             or \"local_address\" and \"local_port\" in configuration file"
        );
        println!("{}", matches.usage());
        return;
    }

    if config.server.is_empty() {
        eprintln!(
            "missing proxy servers, consider specifying it by \
             --server-addr, --encrypt-method, --password command line option, \
                or --server-url command line option, \
                or configuration file, check more details in https://shadowsocks.org/en/config/quick-guide.html"
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
    if matches.is_present("DAEMONIZE") {
        daemonize::daemonize(matches.value_of("DAEMONIZE_PID_PATH"));
    }

    info!("shadowsocks {}", self::version::VERSION);

    let mut builder = if cfg!(feature = "single-threaded") {
        Builder::new_current_thread()
    } else {
        Builder::new_multi_thread()
    };
    let runtime = builder.enable_all().build().expect("create tokio Runtime");
    runtime.block_on(async move {
        let abort_signal = monitor::create_signal_monitor();
        let server = run_local(config);

        tokio::pin!(abort_signal);
        tokio::pin!(server);

        match future::select(server, abort_signal).await {
            // Server future resolved without an error. This should never happen.
            Either::Left((Ok(..), ..)) => panic!("server exited unexpectly"),
            // Server future resolved with error, which are listener errors in most cases
            Either::Left((Err(err), ..)) => panic!("aborted with {}", err),
            // The abort signal future resolved. Means we should just exit.
            Either::Right(_) => (),
        }
    });
}
