//! This is a binary runing in the local environment
//!
//! You have to provide all needed configuration attributes via command line parameters,
//! or you could specify a configuration file. The format of configuration file is defined
//! in mod `config`.
//!

extern crate clap;
extern crate shadowsocks;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate time;

use clap::{App, Arg};

use std::env;
use std::net::SocketAddr;

use env_logger::LogBuilder;
use log::{LogLevelFilter, LogRecord};

use shadowsocks::{Config, ConfigType, ServerAddr, ServerConfig, run_local};
use shadowsocks::plugin::PluginConfig;

fn log_time(without_time: bool, record: &LogRecord) -> String {
    if without_time {
        format!("[{}] {}", record.level(), record.args())
    } else {
        format!("[{}][{}] {}", time::now().strftime("%Y-%m-%d][%H:%M:%S.%f").unwrap(), record.level(), record.args())
    }
}

fn log_time_module(without_time: bool, record: &LogRecord) -> String {
    if without_time {
        format!("[{}] [{}] {}", record.level(), record.location().module_path(), record.args())
    } else {
        format!("[{}][{}] [{}] {}",
                time::now().strftime("%Y-%m-%d][%H:%M:%S.%f").unwrap(),
                record.level(),
                record.location().module_path(),
                record.args())
    }
}

fn main() {
    let matches = App::new("shadowsocks")
        .version(shadowsocks::VERSION)
        .about("A fast tunnel proxy that helps you bypass firewalls.")
        .arg(Arg::with_name("VERBOSE")
                 .short("v")
                 .multiple(true)
                 .help("Set the level of debug"))
        .arg(Arg::with_name("ENABLE_UDP")
                 .short("u")
                 .long("enable-udp")
                 .help("Enable UDP relay"))
        .arg(Arg::with_name("CONFIG")
                 .short("c")
                 .long("config")
                 .takes_value(true)
                 .help("Specify config file"))
        .arg(Arg::with_name("SERVER_ADDR")
                 .short("s")
                 .long("server-addr")
                 .takes_value(true)
                 .help("Server address"))
        .arg(Arg::with_name("LOCAL_ADDR")
                 .short("b")
                 .long("local-addr")
                 .takes_value(true)
                 .help("Local address, listen only to this address if specified"))
        .arg(Arg::with_name("PASSWORD")
                 .short("k")
                 .long("password")
                 .takes_value(true)
                 .help("Password"))
        .arg(Arg::with_name("ENCRYPT_METHOD")
                 .short("m")
                 .long("encrypt-method")
                 .takes_value(true)
                 .help("Encryption method"))
        .arg(Arg::with_name("PLUGIN")
                 .long("plugin")
                 .takes_value(true)
                 .help("Enable SIP003 plugin"))
        .arg(Arg::with_name("PLUGIN_OPT")
                 .long("plugin-opts")
                 .takes_value(true)
                 .help("Set SIP003 plugin options"))
        .arg(Arg::with_name("LOG_WITHOUT_TIME")
                 .long("log-without-time")
                 .help("Disable time in log"))
        .arg(Arg::with_name("URL")
                 .long("server-url")
                 .takes_value(true)
                 .help("Server address in SIP002 URL"))
        .get_matches();

    let mut log_builder = LogBuilder::new();
    log_builder.filter(None, LogLevelFilter::Info);

    let without_time = matches.is_present("LOG_WITHOUT_TIME");

    let debug_level = matches.occurrences_of("VERBOSE");
    match debug_level {
        0 => {
            // Default filter
            log_builder.format(move |r| log_time(without_time, r));
        }
        1 => {
            let log_builder = log_builder.format(move |r| log_time_module(without_time, r));
            log_builder.filter(Some("sslocal"), LogLevelFilter::Debug);
        }
        2 => {
            let log_builder = log_builder.format(move |r| log_time_module(without_time, r));
            log_builder.filter(Some("sslocal"), LogLevelFilter::Debug)
                       .filter(Some("shadowsocks"), LogLevelFilter::Debug);
        }
        3 => {
            let log_builder = log_builder.format(move |r| log_time_module(without_time, r));
            log_builder.filter(Some("sslocal"), LogLevelFilter::Trace)
                       .filter(Some("shadowsocks"), LogLevelFilter::Trace);
        }
        _ => {
            let log_builder = log_builder.format(move |r| log_time_module(without_time, r));
            log_builder.filter(None, LogLevelFilter::Trace);
        }
    }

    if let Ok(env_conf) = env::var("RUST_LOG") {
        log_builder.parse(&env_conf);
    }

    log_builder.init().unwrap();

    let mut has_provided_config = false;

    let mut config = match matches.value_of("CONFIG") {
        Some(cpath) => {
            match Config::load_from_file(cpath, ConfigType::Local) {
                Ok(cfg) => {
                    has_provided_config = true;
                    cfg
                }
                Err(err) => {
                    error!("{:?}", err);
                    return;
                }
            }
        }
        None => Config::new(),
    };

    let mut has_provided_server_config =
        match (matches.value_of("SERVER_ADDR"), matches.value_of("PASSWORD"), matches.value_of("ENCRYPT_METHOD")) {
            (Some(svr_addr), Some(password), Some(method)) => {
                let method = match method.parse() {
                    Ok(m) => m,
                    Err(err) => {
                        panic!("Does not support {:?} method: {:?}", method, err);
                    }
                };

                let sc = ServerConfig::new(svr_addr.parse::<ServerAddr>().expect("Invalid server addr"),
                                           password.to_owned(),
                                           method,
                                           None,
                                           None);

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
            let local_addr: SocketAddr =
                local_addr.parse()
                          .expect("`local-addr` is not a valid IP address");

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

    config.enable_udp |= matches.is_present("ENABLE_UDP");

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

    run_local(config).unwrap();
}
