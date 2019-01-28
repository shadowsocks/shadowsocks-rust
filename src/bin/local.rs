//! This is a binary running in the local environment
//!
//! You have to provide all needed configuration attributes via command line parameters,
//! or you could specify a configuration file. The format of configuration file is defined
//! in mod `config`.

use std::{net::SocketAddr, process};

use clap::{App, Arg};
use futures::{future::Either, Future};
use log::{debug, error, info};
use tokio::runtime::Runtime;

use shadowsocks::{plugin::PluginConfig, run_local, Config, ConfigType, Mode, ServerAddr, ServerConfig};

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
            Arg::with_name("LOG_WITHOUT_TIME")
                .long("log-without-time")
                .help("Disable time in log"),
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
        .get_matches();

    let without_time = matches.is_present("LOG_WITHOUT_TIME");
    let debug_level = matches.occurrences_of("VERBOSE");

    logging::init(without_time, debug_level, "sslocal");

    let mut has_provided_config = false;

    let mut config = match matches.value_of("CONFIG") {
        Some(cpath) => match Config::load_from_file(cpath, ConfigType::Local) {
            Ok(cfg) => {
                has_provided_config = true;
                cfg
            }
            Err(err) => {
                error!("{:?}", err);
                return;
            }
        },
        None => Config::new(ConfigType::Local),
    };

    let mut has_provided_server_config = match (
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
                svr_addr.parse::<ServerAddr>().expect("Invalid server addr"),
                password.to_owned(),
                method,
                None,
                None,
            );

            config.server.push(sc);
            true
        }
        (None, None, None) => {
            // Does not provide server config
            false
        }
        _ => {
            panic!("`server-addr`, `method` and `password` should be provided together");
        }
    };

    if let Some(url) = matches.value_of("URL") {
        let svr_addr = url.parse::<ServerConfig>().expect("Failed to parse `url`");

        has_provided_server_config = true;

        config.server.push(svr_addr);
    }

    let has_provided_local_config = match matches.value_of("LOCAL_ADDR") {
        Some(local_addr) => {
            let local_addr: SocketAddr = local_addr.parse().expect("`local-addr` is not a valid IP address");

            config.local = Some(local_addr);
            true
        }
        None => false,
    };

    if !has_provided_config && !(has_provided_server_config && has_provided_local_config) {
        println!("You have to specify a configuration file or pass arguments by argument list");
        println!("{}", matches.usage());
        return;
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

    info!("ShadowSocks {}", shadowsocks::VERSION);

    debug!("Config: {:?}", config);

    let mut runtime = Runtime::new().expect("Creating runtime");

    let abort_signal = monitor::create_signal_monitor();
    let result = runtime.block_on(run_local(config).select2(abort_signal));

    runtime.shutdown_now().wait().unwrap();

    match result {
        // Server future resolved without an error. This should never happen.
        Ok(Either::A(_)) => panic!("Server exited unexpectly"),
        // Server future resolved with an error.
        Err(Either::A((err, _))) => {
            error!("Server exited unexpectly with error: {}", err);
            process::exit(1);
        }
        // The abort signal future resolved. Means we should just exit.
        Ok(Either::B(..)) | Err(Either::B(..)) => (),
    }
}
