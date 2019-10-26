//! This is a binary running in the server environment
//!
//! You have to provide all needed configuration attributes via command line parameters,
//! or you could specify a configuration file. The format of configuration file is defined
//! in mod `config`.
//!
//! *It should be notice that the extented configuration file is not suitable for the server
//! side.*

use std::{io::Result as IoResult, process};

use clap::{App, Arg};
use futures::{
    future::{self, Either},
    FutureExt,
};
use log::{debug, error, info};
#[cfg(feature = "single-threaded")]
use tokio::runtime::current_thread::Runtime;
#[cfg(not(feature = "single-threaded"))]
use tokio::runtime::Runtime;

use shadowsocks::{plugin::PluginConfig, run_server, Config, ConfigType, Mode, ServerAddr, ServerConfig};

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
        .get_matches();

    let without_time = matches.is_present("LOG_WITHOUT_TIME");
    let debug_level = matches.occurrences_of("VERBOSE");

    logging::init(without_time, debug_level, "ssserver");

    let mut has_provided_config = false;
    let mut config = match matches.value_of("CONFIG") {
        Some(cpath) => match Config::load_from_file(cpath, ConfigType::Server) {
            Ok(cfg) => {
                has_provided_config = true;
                cfg
            }
            Err(err) => {
                error!("{:?}", err);
                return;
            }
        },
        None => Config::new(ConfigType::Server),
    };

    let has_provided_server_config = match (
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

    if !has_provided_config && !has_provided_server_config {
        println!("You have to specify a configuration file or pass arguments from argument list");
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

    if let Some(m) = matches.value_of("MANAGER_ADDRESS") {
        config.manager_address = Some(
            m.parse::<ServerAddr>()
                .expect("Expecting a valid ServerAddr for manager_address"),
        );
    }

    info!("ShadowSocks {}", shadowsocks::VERSION);

    debug!("Config: {:?}", config);

    match launch_server(config) {
        Ok(()) => {}
        Err(err) => {
            error!("Server exited unexpectly with error: {}", err);
            process::exit(1);
        }
    }
}

#[cfg(not(feature = "single-threaded"))]
fn launch_server(config: Config) -> IoResult<()> {
    let runtime = Runtime::new().expect("Creating runtime");

    let abort_signal = monitor::create_signal_monitor();
    let result = runtime.block_on(future::select(run_server(config).boxed(), abort_signal.boxed()));

    runtime.shutdown_now();

    match result {
        // Server future resolved without an error. This should never happen.
        Either::Left(_) => panic!("Server exited unexpectly"),
        // The abort signal future resolved. Means we should just exit.
        Either::Right(_) => (),
    }

    Ok(())
}

#[cfg(feature = "single-threaded")]
fn launch_server(config: Config) -> IoResult<()> {
    let mut runtime = Runtime::new().expect("Creating runtime");

    let abort_signal = monitor::create_signal_monitor();
    let result = runtime.block_on(future::select(run_server(config).boxed(), abort_signal.boxed()));

    match result {
        // Server future resolved without an error. This should never happen.
        Either::Left(_) => panic!("Server exited unexpectly"),
        // The abort signal future resolved. Means we should just exit.
        Either::Right(_) => (),
    }
}
