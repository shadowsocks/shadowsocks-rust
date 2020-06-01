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
    run_manager,
    Config,
    ConfigType,
    ManagerAddr,
    ManagerConfig,
    Mode,
    ServerAddr,
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

        (@arg CONFIG: -c --config +takes_value required_unless("MANAGER_ADDRESS") +next_line_help
            "Shadowsocks configuration file (https://shadowsocks.org/en/config/quick-guide.html), \
                the only required fields are \"manager_address\" and \"manager_port\". \
                Servers defined will be created when process is started.")

        (@arg BIND_ADDR: -b --("bind-addr") +takes_value "Bind address, outbound socket will bind this address")

        (@arg NO_DELAY: --("no-delay") !takes_value "Set no-delay option for socket")

        (@arg MANAGER_ADDRESS: --("manager-address") +takes_value {validator::validate_manager_addr} "ShadowSocks Manager (ssmgr) address, could be ip:port, domain:port or /path/to/unix.sock")
        (@arg ENCRYPT_METHOD: -m --("encrypt-method") +takes_value possible_values(&available_ciphers) +next_line_help "Default encryption method")
        (@arg TIMEOUT: --timeout +takes_value {validator::validate_u64} "Default timeout seconds for TCP relay")

        (@arg NOFILE: -n --nofile +takes_value "Set RLIMIT_NOFILE with both soft and hard limit (only for *nix systems)")
        (@arg ACL: --acl +takes_value "Path to ACL (Access Control List)")
        (@arg LOG_WITHOUT_TIME: --("log-without-time") "Log without datetime prefix")
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
    logging::init(debug_level, "ssmanager", matches.is_present("LOG_WITHOUT_TIME"));

    let mut config = match matches.value_of("CONFIG") {
        Some(cpath) => match Config::load_from_file(cpath, ConfigType::Manager) {
            Ok(cfg) => cfg,
            Err(err) => {
                panic!("loading config \"{}\", {}", cpath, err);
            }
        },
        None => Config::new(ConfigType::Manager),
    };

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
        if let Some(ref mut manager_config) = config.manager {
            manager_config.addr = m.parse::<ManagerAddr>().expect("manager-address");
        } else {
            config.manager = Some(ManagerConfig::new(m.parse::<ManagerAddr>().expect("manager-address")));
        }
    }

    if let Some(ref mut manager_config) = config.manager {
        if let Some(m) = matches.value_of("ENCRYPT_METHOD") {
            manager_config.method = Some(m.parse::<CipherType>().expect("encrypt-method"));
        }

        if let Some(t) = matches.value_of("TIMEOUT") {
            manager_config.timeout = Some(Duration::from_secs(t.parse::<u64>().expect("timeout")));
        }
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

    // DONE reading options

    if config.manager.is_none() {
        eprintln!(
            "missing `manager_address`, consider specifying it by --manager-address command line option, \
             or \"manager_address\" and \"manager_port\" keys in configuration file"
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
        let server = run_manager(config);

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
