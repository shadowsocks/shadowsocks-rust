//! This is a binary running in the local environment
//!
//! You have to provide all needed configuration attributes via command line parameters,
//! or you could specify a configuration file. The format of configuration file is defined
//! in mod `config`.

use clap::{App, Arg};
use futures::{
    future::{self, Either},
    FutureExt,
};
use log::{error, info};
use tokio::runtime::Builder;

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

fn main() {
    let matches = App::new("shadowsocks")
        .version(shadowsocks::VERSION)
        .about("A fast tunnel proxy that helps you bypass firewalls.")
        .arg(
            Arg::with_name("VERBOSE")
                .short("v")
                .multiple(true)
                .help("Set the level of debug"),
        )
        .arg(
            Arg::with_name("STAT_PATH")
                .long("stat-path")
                .takes_value(true)
                .help("Specify stat path (only for Android)"),
        )
        .arg(
            Arg::with_name("PROTECT_PATH")
                .long("protect-path")
                .takes_value(true)
                .help("Specify protect-path (only for Android)"),
        )
        .arg(Arg::with_name("UDP_ONLY").short("u").help("Server mode UDP_ONLY"))
        .arg(Arg::with_name("TCP_AND_UDP").short("U").help("Server mode TCP_AND_UDP"))
        .arg(
            Arg::with_name("CONFIG")
                .short("c")
                .long("config")
                .takes_value(true)
                .help("Specify config file"),
        )
        .arg(
            Arg::with_name("SERVER_ADDR")
                .short("s")
                .long("server-addr")
                .takes_value(true)
                .help("Server address"),
        )
        .arg(
            Arg::with_name("LOCAL_ADDR")
                .short("b")
                .long("local-addr")
                .takes_value(true)
                .help("Local address, listen only to this address if specified"),
        )
        .arg(
            Arg::with_name("PASSWORD")
                .short("k")
                .long("password")
                .takes_value(true)
                .help("Password"),
        )
        .arg(
            Arg::with_name("ENCRYPT_METHOD")
                .short("m")
                .long("encrypt-method")
                .takes_value(true)
                .help("Encryption method")
                .long_help(format!("Available ciphers: {}", CipherType::available_ciphers().join(", ")).as_str()),
        )
        .arg(
            Arg::with_name("PLUGIN")
                .long("plugin")
                .takes_value(true)
                .help("Enable SIP003 plugin"),
        )
        .arg(
            Arg::with_name("PLUGIN_OPT")
                .long("plugin-opts")
                .takes_value(true)
                .help("Set SIP003 plugin options"),
        )
        .arg(
            Arg::with_name("URL")
                .long("server-url")
                .takes_value(true)
                .help("Server address in SIP002 URL"),
        )
        .arg(
            Arg::with_name("NO_DELAY")
                .long("no-delay")
                .takes_value(false)
                .help("Set no-delay option for socket"),
        )
        .arg(
            Arg::with_name("PROTOCOL")
                .long("protocol")
                .takes_value(true)
                .help("Protocol that uses to communicates with clients, `socks5` or `http`, default is `socks5`"),
        )
        .arg(
            Arg::with_name("NOFILE")
                .short("n")
                .long("nofile")
                .takes_value(true)
                .help("Set RLIMIT_NOFILE with both soft and hard limit (only for *nix systems)"),
        )
        .arg(
            Arg::with_name("ACL")
                .long("acl")
                .takes_value(true)
                .help("Path to ACL (Access Control List)"),
        )
        .get_matches();

    let debug_level = matches.occurrences_of("VERBOSE");
    logging::init(debug_level, "sslocal");

    let config_type = match matches.value_of("PROTOCOL") {
        Some("socks5") => ConfigType::Socks5Local,
        Some("http") => ConfigType::HttpLocal,
        Some(..) => panic!("`protocol` only supports `socks5` or `http`"),
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

    match (
        matches.value_of("SERVER_ADDR"),
        matches.value_of("PASSWORD"),
        matches.value_of("ENCRYPT_METHOD"),
    ) {
        (Some(svr_addr), Some(password), Some(method)) => {
            let method = match method.parse() {
                Ok(m) => m,
                Err(err) => {
                    panic!("does not support {:?} method: {:?}", method, err);
                }
            };

            let sc = ServerConfig::new(
                svr_addr
                    .parse::<ServerAddr>()
                    .expect("`server-addr` invalid, \"IP:Port\" or \"Domain:Port\""),
                password.to_owned(),
                method,
                None,
                None,
            );

            config.server.push(sc);
        }
        (None, None, None) => {
            // Does not provide server config
        }
        _ => {
            panic!("`server-addr`, `method` and `password` should be provided together");
        }
    };

    if let Some(stat_path) = matches.value_of("STAT_PATH") {
        config.stat_path = Some(stat_path.to_string());
    }

    if let Some(protect_path) = matches.value_of("PROTECT_PATH") {
        config.protect_path = Some(protect_path.to_string());
    }

    if let Some(url) = matches.value_of("URL") {
        let svr_addr = url.parse::<ServerConfig>().expect("parse `url`");
        config.server.push(svr_addr);
    }

    if let Some(local_addr) = matches.value_of("LOCAL_ADDR") {
        let local_addr = local_addr
            .parse::<ServerAddr>()
            .expect("`local-addr` should be \"IP:Port\" or \"Domain:Port\"");

        config.local = Some(local_addr);
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

    if let Some(p) = matches.value_of("PLUGIN") {
        let plugin = PluginConfig {
            plugin: p.to_owned(),
            plugin_opt: matches.value_of("PLUGIN_OPT").map(ToOwned::to_owned),
        };

        // Overrides config in file
        for svr in config.server.iter_mut() {
            svr.set_plugin(plugin.clone());
        }
    };

    if let Some(nofile) = matches.value_of("NOFILE") {
        config.nofile = Some(nofile.parse::<u64>().expect("an unsigned integer for `nofile`"));
    }

    if let Some(acl_file) = matches.value_of("ACL") {
        let acl = AccessControl::load_from_file(acl_file).expect("Load ACL file");
        config.acl = Some(acl);
    }

    if config.local.is_none() {
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
        match future::select(run_local(config, rt_handle).boxed(), abort_signal.boxed()).await {
            // Server future resolved without an error. This should never happen.
            Either::Left((Ok(..), ..)) => panic!("server exited unexpectly"),
            // Server future resolved with error, which are listener errors in most cases
            Either::Left((Err(err), ..)) => panic!("server exited unexpectly with {}", err),
            // The abort signal future resolved. Means we should just exit.
            Either::Right(_) => (),
        }
    })
}
