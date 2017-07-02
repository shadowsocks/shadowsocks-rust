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
extern crate num_cpus;

use clap::{App, Arg};

use std::net::SocketAddr;
use std::env;

use env_logger::LogBuilder;
use log::{LogRecord, LogLevelFilter};

use shadowsocks::{Config, ServerConfig, ServerAddr, ConfigType, run_local};

fn main() {
    let matches = App::new("shadowsocks")
        .version(shadowsocks::VERSION)
        .author("Y. T. Chung <zonyitoo@gmail.com>")
        .about("A fast tunnel proxy that helps you bypass firewalls.")
        .arg(Arg::with_name("VERBOSE").short("v").multiple(true).help(
            "Set the level of debug",
        ))
        .arg(
            Arg::with_name("ENABLE_UDP")
                .short("u")
                .long("enable-udp")
                .help("Enable UDP relay"),
        )
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
        .get_matches();

    let mut log_builder = LogBuilder::new();
    log_builder.filter(None, LogLevelFilter::Info);

    let debug_level = matches.occurrences_of("VERBOSE");
    match debug_level {
        0 => {
            // Default filter
            log_builder.format(|record: &LogRecord| {
                format!(
                    "[{}][{}] {}",
                    time::now().strftime("%Y-%m-%d][%H:%M:%S").unwrap(),
                    record.level(),
                    record.args()
                )
            });
        }
        1 => {
            let mut log_builder = log_builder.format(|record: &LogRecord| {
                format!(
                    "[{}][{}] [{}] {}",
                    time::now().strftime("%Y-%m-%d][%H:%M:%S").unwrap(),
                    record.level(),
                    record.location().module_path(),
                    record.args()
                )
            });
            log_builder.filter(Some("sslocal"), LogLevelFilter::Debug);
        }
        2 => {
            let mut log_builder = log_builder.format(|record: &LogRecord| {
                format!(
                    "[{}][{}] [{}] {}",
                    time::now().strftime("%Y-%m-%d][%H:%M:%S").unwrap(),
                    record.level(),
                    record.location().module_path(),
                    record.args()
                )
            });
            log_builder
                .filter(Some("sslocal"), LogLevelFilter::Debug)
                .filter(Some("shadowsocks"), LogLevelFilter::Debug);
        }
        3 => {
            let mut log_builder = log_builder.format(|record: &LogRecord| {
                format!(
                    "[{}][{}] [{}] {}",
                    time::now().strftime("%Y-%m-%d][%H:%M:%S").unwrap(),
                    record.level(),
                    record.location().module_path(),
                    record.args()
                )
            });
            log_builder
                .filter(Some("sslocal"), LogLevelFilter::Trace)
                .filter(Some("shadowsocks"), LogLevelFilter::Trace);
        }
        _ => {
            let mut log_builder = log_builder.format(|record: &LogRecord| {
                format!(
                    "[{}][{}] [{}] {}",
                    time::now().strftime("%Y-%m-%d][%H:%M:%S").unwrap(),
                    record.level(),
                    record.location().module_path(),
                    record.args()
                )
            });
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

    let mut has_provided_server_config = false;

    if matches.value_of("SERVER_ADDR").is_some() && matches.value_of("PASSWORD").is_some() &&
        matches.value_of("ENCRYPT_METHOD").is_some()
    {
        let (svr_addr, password, method) = matches
            .value_of("SERVER_ADDR")
            .and_then(|svr_addr| {
                matches.value_of("PASSWORD").map(|pwd| (svr_addr, pwd))
            })
            .and_then(|(svr_addr, pwd)| {
                matches.value_of("ENCRYPT_METHOD").map(
                    |m| (svr_addr, pwd, m),
                )
            })
            .unwrap();

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
        );

        config.server.push(sc);
        has_provided_server_config = true;
    } else if matches.value_of("SERVER_ADDR").is_none() && matches.value_of("PASSWORD").is_none() &&
               matches.value_of("ENCRYPT_METHOD").is_none()
    {
        // Does not provide server config
    } else {
        panic!("`server-addr`, `method` and `password` should be provided together");
    }

    let has_provided_local_config = if matches.value_of("LOCAL_ADDR").is_some() {
        let local_addr = matches.value_of("LOCAL_ADDR").unwrap();

        let local_addr: SocketAddr = local_addr.parse().expect(
            "`local-addr` is not a valid IP address",
        );

        config.local = Some(local_addr);
        true
    } else {
        false
    };

    if !has_provided_config && !(has_provided_server_config && has_provided_local_config) {
        println!("You have to specify a configuration file or pass arguments by argument list");
        println!("{}", matches.usage());
        return;
    }

    config.enable_udp |= matches.is_present("ENABLE_UDP");

    info!("ShadowSocks {}", shadowsocks::VERSION);

    debug!("Config: {:?}", config);

    run_local(config).unwrap();
}
