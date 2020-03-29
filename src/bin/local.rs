//! This is a binary running in the local environment
//!
//! You have to provide all needed configuration attributes via command line parameters,
//! or you could specify a configuration file. The format of configuration file is defined
//! in mod `config`.

use clap::{clap_app, Arg};
use futures::future::{self, Either};
use log::{error, info};
use tokio::{self, runtime::Builder};

use shadowsocks::{
    acl::AccessControl,
    crypto::CipherType,
    plugin::PluginConfig,
    run_local,
    Config,
    ConfigType,
    Mode,
    ServerAddr,
    ServerConfig,
};

mod logging;
mod monitor;
mod validator;

const AVAILABLE_PROTOCOLS: &[&str] = &[
    "socks5",
    #[cfg(feature = "local-protocol-http")]
    "http",
];

fn main() {
    let available_ciphers = CipherType::available_ciphers();

    let mut app = clap_app!(shadowsocks =>
        (version: shadowsocks::VERSION)
        (about: "A fast tunnel proxy that helps you bypass firewalls.")
        (@arg VERBOSE: -v ... "Set the level of debug")
        (@arg UDP_ONLY: -u conflicts_with[TCP_AND_UDP] "Server mode UDP_ONLY")
        (@arg TCP_AND_UDP: -U conflicts_with[UDP_ONLY] "Server mode TCP_AND_UDP")
        (@arg CONFIG: -c --config +takes_value "Specify config file")
        (@arg LOCAL_ADDR: -b --("local-addr") +takes_value {validator::validate_server_addr} "Local address, listen only to this address if specified")
        (@arg SERVER_ADDR: -s --("server-addr") +takes_value {validator::validate_server_addr} requires[PASSWORD ENCRYPT_METHOD] "Server address")
        (@arg PASSWORD: -k --password +takes_value requires[SERVER_ADDR ENCRYPT_METHOD] "Password")
        (@arg ENCRYPT_METHOD: -m --("encrypt-method") +takes_value possible_values(&available_ciphers) requires[SERVER_ADDR PASSWORD] "Encryption method")
        (@arg PLUGIN: --plugin +takes_value requires[SERVER_ADDR] "SIP003 (https://shadowsocks.org/en/spec/Plugin.html) plugin")
        (@arg PLUGIN_OPT: --("plugin-opts") +takes_value requires[PLUGIN] "Set SIP003 plugin options")
        (@arg URL: --("server-url") +takes_value {validator::validate_server_url} "Server address in SIP002 (https://shadowsocks.org/en/spec/SIP002-URI-Scheme.html) URL")
        (@group SERVER_CONFIG =>
            (@attributes +required ... arg[CONFIG SERVER_ADDR URL])
        )
        (@group LOCAL_CONFIG =>
            (@attributes +required ... arg[CONFIG LOCAL_ADDR])
        )
        (@arg PROTOCOL: --protocol +takes_value default_value("socks5") possible_values(AVAILABLE_PROTOCOLS) "Protocol that for communicating with clients")
        (@arg NO_DELAY: --("no-delay") !takes_value "Set no-delay option for socket")
        (@arg NOFILE: -n --nofile +takes_value "Set RLIMIT_NOFILE with both soft and hard limit (only for *nix systems)")
        (@arg ACL: --acl +takes_value "Path to ACL (Access Control List)")
        (@arg LOG_WITHOUT_TIME: --("log-without-time") "Log without datetime prefix")
    );

    // FIXME: -6 is not a identifier, so we cannot build it with clap_app!
    app = app.arg(
        Arg::with_name("IPV6_FIRST")
            .short("6")
            .help("Resovle hostname to IPv6 address first"),
    );

    if cfg!(target_os = "android") {
        app = clap_app!(@app (app)
            (@arg VPN_MODE: --vpn "Enable VPN mode (only for Android)")
        );
    }

    #[cfg(feature = "local-flow-stat")]
    {
        app = clap_app!(@app (app)
            (@arg STAT_PATH: --("stat-path") +takes_value "Specify stat_path for traffic stat (only for Android)")
        );
    }

    #[cfg(feature = "local-dns-relay")]
    {
        app = clap_app!(@app (app)
            (@arg LOCAL_DNS_ADDR: --("local-dns") +takes_value {validator::validate_socket_addr} default_value("127.0.0.1:5353") "Specify the address of local DNS server (only for Android)")
            (@arg REMOTE_DNS_ADDR: --("remote-dns") +takes_value {validator::validate_address} default_value("8.8.8.8:53") "Specify the address of remote DNS server (only for Android)")
            (@arg DNS_LOCAL_ADDR: --("dns-relay") +takes_value {validator::validate_server_addr} default_value("127.0.0.1:5450") "Specify the address of DNS relay (only for Android)")
        );
    }

    let matches = app.get_matches();
    drop(available_ciphers);

    let debug_level = matches.occurrences_of("VERBOSE");
    logging::init(debug_level, "sslocal", matches.is_present("LOG_WITHOUT_TIME"));

    let config_type = match matches.value_of("PROTOCOL") {
        Some("socks5") => ConfigType::Socks5Local,
        #[cfg(feature = "local-protocol-http")]
        Some("http") => ConfigType::HttpLocal,
        Some(p) => panic!("not supported `protocol` \"{}\"", p),
        None => ConfigType::Socks5Local,
    };

    let mut config = match matches.value_of("CONFIG") {
        Some(cpath) => match Config::load_from_file(cpath, config_type) {
            Ok(cfg) => cfg,
            Err(err) => {
                error!("{:?}", err);
                return;
            }
        },
        None => Config::new(config_type),
    };

    if let Some(svr_addr) = matches.value_of("SERVER_ADDR") {
        let password = matches.value_of("PASSWORD").expect("password");
        let method = matches
            .value_of("ENCRYPT_METHOD")
            .expect("encrypt-method")
            .parse::<CipherType>()
            .expect("encryption method");
        let svr_addr = svr_addr.parse::<ServerAddr>().expect("server-addr");

        let mut sc = ServerConfig::new(svr_addr, password.to_owned(), method, None, None);

        if let Some(p) = matches.value_of("PLUGIN") {
            let plugin = PluginConfig {
                plugin: p.to_owned(),
                plugin_opt: matches.value_of("PLUGIN_OPT").map(ToOwned::to_owned),
            };

            sc.set_plugin(plugin);
        }

        config.server.push(sc);
    }

    if let Some(url) = matches.value_of("URL") {
        let svr_addr = url.parse::<ServerConfig>().expect("server SIP002 url");
        config.server.push(svr_addr);
    }

    if cfg!(target_os = "android") {
        config.local_dns_path = Some(From::from("local_dns_path"));

        if matches.is_present("VPN_MODE") {
            // A socket `protect_path` in CWD
            // Same as shadowsocks-libev's android.c
            config.protect_path = Some(From::from("protect_path"));
        }
    }

    #[cfg(feature = "local-flow-stat")]
    {
        if let Some(stat_path) = matches.value_of("STAT_PATH") {
            config.stat_path = Some(From::from(stat_path));
        }
    }

    #[cfg(feature = "local-dns-relay")]
    {
        use std::net::SocketAddr;

        use shadowsocks::relay::socks5::Address;

        if let Some(local_dns_addr) = matches.value_of("LOCAL_DNS_ADDR") {
            let addr = local_dns_addr.parse::<SocketAddr>().expect("local dns address");
            config.local_dns_addr = Some(addr);
        }

        if let Some(remote_dns_addr) = matches.value_of("REMOTE_DNS_ADDR") {
            let addr = remote_dns_addr.parse::<Address>().expect("remote dns address");
            config.remote_dns_addr = Some(addr);
        }

        if let Some(dns_relay_addr) = matches.value_of("DNS_LOCAL_ADDR") {
            let addr = dns_relay_addr.parse::<ServerAddr>().expect("dns relay address");
            config.dns_local_addr = Some(addr);
        }
    }

    if let Some(local_addr) = matches.value_of("LOCAL_ADDR") {
        let local_addr = local_addr.parse::<ServerAddr>().expect("local bind addr");
        config.local_addr = Some(local_addr);
    }

    if matches.is_present("UDP_ONLY") {
        if config.mode.enable_tcp() {
            config.mode = Mode::TcpAndUdp;
        } else {
            config.mode = Mode::UdpOnly;
        }
    }

    if matches.is_present("TCP_AND_UDP") {
        config.mode = Mode::TcpAndUdp;
    }

    if matches.is_present("NO_DELAY") {
        config.no_delay = true;
    }

    if let Some(nofile) = matches.value_of("NOFILE") {
        config.nofile = Some(nofile.parse::<u64>().expect("an unsigned integer for `nofile`"));
    }

    if let Some(acl_file) = matches.value_of("ACL") {
        let acl = AccessControl::load_from_file(acl_file).expect("load ACL file");
        config.acl = Some(acl);
    }

    if matches.is_present("IPV6_FIRST") {
        config.ipv6_first = true;
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

    info!("shadowsocks {}", shadowsocks::VERSION);

    let mut builder = Builder::new();
    if cfg!(feature = "single-threaded") {
        builder.basic_scheduler();
    } else {
        builder.threaded_scheduler();
    }
    let mut runtime = builder.enable_all().build().expect("create tokio Runtime");
    let rt_handle = runtime.handle().clone();
    runtime.block_on(async move {
        let abort_signal = monitor::create_signal_monitor();
        let server = run_local(config, rt_handle);

        tokio::pin!(abort_signal);
        tokio::pin!(server);

        match future::select(server, abort_signal).await {
            // Server future resolved without an error. This should never happen.
            Either::Left((Ok(..), ..)) => panic!("server exited unexpectly"),
            // Server future resolved with error, which are listener errors in most cases
            Either::Left((Err(err), ..)) => panic!("server exited unexpectly with {}", err),
            // The abort signal future resolved. Means we should just exit.
            Either::Right(_) => (),
        }
    })
}
