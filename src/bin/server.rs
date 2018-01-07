//! This is a binary running in the server environment
//!
//! You have to provide all needed configuration attributes via command line parameters,
//! or you could specify a configuration file. The format of configuration file is defined
//! in mod `config`.
//!
//! *It should be notice that the extented configuration file is not suitable for the server
//! side.*

extern crate clap;
extern crate env_logger;
#[macro_use]
extern crate log;
extern crate shadowsocks;
extern crate time;

use std::env;
use std::io::{self, Write};

use clap::{App, Arg};

use env_logger::Builder;
use env_logger::fmt::Formatter;
use log::{LevelFilter, Record};

use shadowsocks::{Config, ConfigType, ServerAddr, ServerConfig, run_server};
use shadowsocks::plugin::PluginConfig;

fn log_time(fmt: &mut Formatter, without_time: bool, record: &Record) -> io::Result<()> {
    if without_time {
        write!(fmt, "[{}] {}", record.level(), record.args())
    } else {
        write!(fmt, "[{}][{}] {}", time::now().strftime("%Y-%m-%d][%H:%M:%S.%f").unwrap(), record.level(), record.args())
    }
}

fn log_time_module(fmt: &mut Formatter, without_time: bool, record: &Record) -> io::Result<()> {
    if without_time {
        write!(fmt, "[{}] [{}] {}", record.level(), record.module_path().unwrap_or("*"), record.args())
    } else {
        write!(fmt, "[{}][{}] [{}] {}",
                time::now().strftime("%Y-%m-%d][%H:%M:%S.%f").unwrap(),
                record.level(),
                record.module_path().unwrap_or("*"),
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
        .get_matches();

    let mut log_builder = Builder::new();
    log_builder.filter(None, LevelFilter::Info);

    let without_time = matches.is_present("LOG_WITHOUT_TIME");

    let debug_level = matches.occurrences_of("VERBOSE");
    match debug_level {
        0 => {
            // Default filter
            log_builder.format(move |fmt, r| log_time(fmt, without_time, r));
        }
        1 => {
            let log_builder = log_builder.format(move |fmt, r| log_time_module(fmt, without_time, r));
            log_builder.filter(Some("ssserver"), LevelFilter::Debug);
        }
        2 => {
            let log_builder = log_builder.format(move |fmt, r| log_time_module(fmt, without_time, r));
            log_builder.filter(Some("ssserver"), LevelFilter::Debug)
                       .filter(Some("shadowsocks"), LevelFilter::Debug);
        }
        3 => {
            let log_builder = log_builder.format(move |fmt, r| log_time_module(fmt, without_time, r));
            log_builder.filter(Some("ssserver"), LevelFilter::Trace)
                       .filter(Some("shadowsocks"), LevelFilter::Trace);
        }
        _ => {
            let log_builder = log_builder.format(move |fmt, r| log_time_module(fmt, without_time, r));
            log_builder.filter(None, LevelFilter::Trace);
        }
    }

    if let Ok(env_conf) = env::var("RUST_LOG") {
        log_builder.parse(&env_conf);
    }

    log_builder.init();

    let mut has_provided_config = false;
    let mut config = match matches.value_of("CONFIG") {
        Some(cpath) => {
            match Config::load_from_file(cpath, ConfigType::Server) {
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

    let has_provided_server_config =
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

    if !has_provided_config && !has_provided_server_config {
        println!("You have to specify a configuration file or pass arguments from argument list");
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

    run_server(config).unwrap();
}
