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
    config::RedirType,
    crypto::CipherType,
    plugin::PluginConfig,
    relay::socks5::Address,
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

fn main() {
    let available_ciphers = CipherType::available_ciphers();
    let available_redir_types = RedirType::available_types();

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
        (@arg NO_DELAY: --("no-delay") !takes_value "Set no-delay option for socket")
        (@arg NOFILE: -n --nofile +takes_value "Set RLIMIT_NOFILE with both soft and hard limit (only for *nix systems)")
        (@arg ACL: --acl +takes_value "Path to ACL (Access Control List)")
        (@arg LOG_WITHOUT_TIME: --("log-without-time") "Log without datetime prefix")
    );

    app = app.arg(
        Arg::with_name("IPV6_FIRST")
            .short("6")
            .help("Resovle hostname to IPv6 address first"),
    );

    let available_types = RedirType::available_types();

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

    let matches = app.get_matches();

    drop(available_ciphers);
    drop(available_redir_types);

    let debug_level = matches.occurrences_of("VERBOSE");
    logging::init(debug_level, "ssredir", matches.is_present("LOG_WITHOUT_TIME"));

    let mut config = match matches.value_of("CONFIG") {
        Some(cpath) => match Config::load_from_file(cpath, ConfigType::RedirLocal) {
            Ok(cfg) => cfg,
            Err(err) => {
                error!("{:?}", err);
                return;
            }
        },
        None => Config::new(ConfigType::RedirLocal),
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

    if let Some(tcp_redir) = matches.value_of("TCP_REDIR") {
        config.tcp_redir = tcp_redir.parse::<RedirType>().expect("TCP redir type");
    }

    if let Some(udp_redir) = matches.value_of("UDP_REDIR") {
        config.udp_redir = udp_redir.parse::<RedirType>().expect("UDP redir type");
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
