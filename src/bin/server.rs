//! This is a binary running in the server environment
//!
//! You have to provide all needed configuration attributes via command line parameters,
//! or you could specify a configuration file. The format of configuration file is defined
//! in mod `config`.
//!
//! *It should be notice that the extented configuration file is not suitable for the server
//! side.*

use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use clap::{clap_app, Arg};
use futures::future::{self, Either};
use log::info;
use tokio::{self, runtime::Builder};

use shadowsocks::{
    acl::AccessControl,
    crypto::CipherType,
    plugin::PluginConfig,
    run_server,
    Config,
    ConfigType,
    ManagerAddr,
    ManagerConfig,
    Mode,
    ServerAddr,
    ServerConfig,
};

mod logging;
mod monitor;
mod validator;

fn main() {
    let available_ciphers = CipherType::available_ciphers();

    let app = clap_app!(shadowsocks =>
        (version: shadowsocks::VERSION)
        (about: "A fast tunnel proxy that helps you bypass firewalls.")
        (@arg VERBOSE: -v ... "Set the level of debug")
        (@arg UDP_ONLY: -u conflicts_with[TCP_AND_UDP] "Server mode UDP_ONLY")
        (@arg TCP_AND_UDP: -U conflicts_with[UDP_ONLY] "Server mode TCP_AND_UDP")

        (@arg CONFIG: -c --config +takes_value required_unless("SERVER_ADDR") "Shadowsocks configuration file (https://shadowsocks.org/en/config/quick-guide.html)")

        (@arg BIND_ADDR: -b --("bind-addr") +takes_value "Bind address, outbound socket will bind this address")

        (@arg SERVER_ADDR: -s --("server-addr") +takes_value {validator::validate_server_addr} requires[PASSWORD ENCRYPT_METHOD] "Server address")
        (@arg PASSWORD: -k --password +takes_value requires[SERVER_ADDR] "Server's password")
        (@arg ENCRYPT_METHOD: -m --("encrypt-method") +takes_value possible_values(&available_ciphers) requires[SERVER_ADDR] "Server's encryption method")
        (@arg TIMEOUT: --timeout +takes_value {validator::validate_u64} requires[SERVER_ADDR] "Server's timeout seconds for TCP relay")

        (@arg PLUGIN: --plugin +takes_value requires[SERVER_ADDR] "SIP003 (https://shadowsocks.org/en/spec/Plugin.html) plugin")
        (@arg PLUGIN_OPT: --("plugin-opts") +takes_value requires[PLUGIN] "Set SIP003 plugin options")

        (@arg MANAGER_ADDRESS: --("manager-address") +takes_value "ShadowSocks Manager (ssmgr) address, could be \"IP:Port\", \"Domain:Port\" or \"/path/to/unix.sock\"")

        (@arg NO_DELAY: --("no-delay") !takes_value "Set no-delay option for socket")
        (@arg NOFILE: -n --nofile +takes_value "Set RLIMIT_NOFILE with both soft and hard limit (only for *nix systems)")
        (@arg ACL: --acl +takes_value "Path to ACL (Access Control List)")
        (@arg LOG_WITHOUT_TIME: --("log-without-time") "Log without datetime prefix")

        (@arg UDP_TIMEOUT: --("udp-timeout") +takes_value {validator::validate_u64} "Timeout seconds for UDP relay")
        (@arg UDP_MAX_ASSOCIATIONS: --("udp-max-associations") +takes_value {validator::validate_u64} "Maximum associations to be kept simultaneously for UDP relay")
    );

    let matches = app
        .arg(
            Arg::with_name("IPV6_FIRST")
                .short("6")
                .help("Resolve hostname to IPv6 address first"),
        )
        .get_matches();

    drop(available_ciphers);

    let debug_level = matches.occurrences_of("VERBOSE");
    logging::init(debug_level, "ssserver", matches.is_present("LOG_WITHOUT_TIME"));

    let mut config = match matches.value_of("CONFIG") {
        Some(cpath) => match Config::load_from_file(cpath, ConfigType::Server) {
            Ok(cfg) => cfg,
            Err(err) => {
                panic!("loading config \"{}\", {}", cpath, err);
            }
        },
        None => Config::new(ConfigType::Server),
    };

    if let Some(svr_addr) = matches.value_of("SERVER_ADDR") {
        let password = matches.value_of("PASSWORD").expect("password");
        let method = matches
            .value_of("ENCRYPT_METHOD")
            .expect("encrypt-method")
            .parse::<CipherType>()
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
                plugin_opt: matches.value_of("PLUGIN_OPT").map(ToOwned::to_owned),
            };

            sc.set_plugin(plugin);
        }

        config.server.push(sc);
    }

    if let Some(bind_addr) = matches.value_of("BIND_ADDR") {
        let bind_addr = match bind_addr.parse::<IpAddr>() {
            Ok(ip) => ServerAddr::from(SocketAddr::new(ip, 0)),
            Err(..) => ServerAddr::from((bind_addr, 0)),
        };

        config.local_addr = Some(bind_addr);
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

    if let Some(m) = matches.value_of("MANAGER_ADDRESS") {
        config.manager = Some(ManagerConfig::new(m.parse::<ManagerAddr>().expect("manager address")));
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

    if let Some(udp_timeout) = matches.value_of("UDP_TIMEOUT") {
        config.udp_timeout = Some(Duration::from_secs(udp_timeout.parse::<u64>().expect("udp-timeout")));
    }

    if let Some(udp_max_assoc) = matches.value_of("UDP_MAX_ASSOCIATIONS") {
        config.udp_max_associations = Some(udp_max_assoc.parse::<usize>().expect("udp-max-associations"));
    }

    // DONE READING options

    if config.server.is_empty() {
        eprintln!(
            "missing proxy servers, consider specifying it by \
             --server-addr, --encrypt-method, --password command line option, \
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
    runtime.block_on(async move {
        let abort_signal = monitor::create_signal_monitor();
        let server = run_server(config);

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
