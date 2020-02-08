//! This is a binary running in the server environment
//!
//! You have to provide all needed configuration attributes via command line parameters,
//! or you could specify a configuration file. The format of configuration file is defined
//! in mod `config`.
//!
//! *It should be notice that the extented configuration file is not suitable for the server
//! side.*

use std::net::{IpAddr, SocketAddr};

use clap::{App, Arg};
use futures::{
    future::{self, Either},
    FutureExt,
};
use log::{error, info};
use tokio::runtime::Builder;

use shadowsocks::{plugin::PluginConfig, run_manager, Config, ConfigType, Mode, ServerAddr, ServerConfig};

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
            Arg::with_name("BIND_ADDR")
                .short("b")
                .long("bind-addr")
                .takes_value(true)
                .help("Bind address, outbound socket will bind this address"),
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
                .help("Encryption method"),
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
            Arg::with_name("NO_DELAY")
                .long("no-delay")
                .takes_value(false)
                .help("Set no-delay option for socket"),
        )
        .arg(
            Arg::with_name("MANAGER_ADDRESS")
                .long("manager-address")
                .takes_value(true)
                .help("ShadowSocks Manager (ssmgr) address"),
        )
        .arg(
            Arg::with_name("NOFILE")
                .short("n")
                .long("nofile")
                .takes_value(true)
                .help("Set RLIMIT_NOFILE with both soft and hard limit (only for *nix systems)"),
        )
        .get_matches();

    let debug_level = matches.occurrences_of("VERBOSE");
    logging::init(debug_level, "ssmanager");

    let mut config = match matches.value_of("CONFIG") {
        Some(cpath) => match Config::load_from_file(cpath, ConfigType::Manager) {
            Ok(cfg) => cfg,
            Err(err) => {
                error!("{:?}", err);
                return;
            }
        },
        None => Config::new(ConfigType::Manager),
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
                    panic!("Does not support {:?} method: {:?}", method, err);
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

    if let Some(bind_addr) = matches.value_of("BIND_ADDR") {
        let bind_addr = match bind_addr.parse::<IpAddr>() {
            Ok(ip) => ServerAddr::from(SocketAddr::new(ip, 0)),
            Err(..) => ServerAddr::from((bind_addr, 0)),
        };

        config.local = Some(bind_addr);
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

    if let Some(m) = matches.value_of("MANAGER_ADDRESS") {
        config.manager_address = Some(
            m.parse::<ServerAddr>()
                .expect("Expecting \"IP:Port\" or \"Domain:Port\" for `manager_address`"),
        );
    }

    if let Some(nofile) = matches.value_of("NOFILE") {
        config.nofile = Some(
            nofile
                .parse::<u64>()
                .expect("Expecting an unsigned integer for `nofile`"),
        );
    }

    info!("ShadowSocks {}", shadowsocks::VERSION);

    if config.manager_address.is_none() {
        error!(
            "Missing `manager_address`, could be specified by --manager-address in command line option or \"manager_address\" key in configuration"
        );

        println!("{}", matches.usage());
        return;
    }

    let mut builder = Builder::new();
    if cfg!(feature = "single-threaded") {
        builder.basic_scheduler();
    } else {
        builder.threaded_scheduler();
    }
    let mut runtime = builder.enable_all().build().expect("Unable to create Tokio Runtime");
    let rt_handle = runtime.handle().clone();

    runtime.block_on(async move {
        let abort_signal = monitor::create_signal_monitor();
        match future::select(run_manager(config, rt_handle).boxed(), abort_signal.boxed()).await {
            // Server future resolved without an error. This should never happen.
            Either::Left(_) => panic!("Server exited unexpectly"),
            // The abort signal future resolved. Means we should just exit.
            Either::Right(_) => (),
        }
    })
}
