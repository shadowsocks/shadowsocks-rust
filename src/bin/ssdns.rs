//! DNS over shadowsocks

use std::net::SocketAddr;

use clap::{App, Arg};
use futures::Future;
use log::{debug, error, info};
use tokio::runtime::Runtime;

use shadowsocks::{run_dns, Config, ConfigType, ServerAddr, ServerConfig};

mod logging;

fn main() {
    let matches = App::new("ssdns")
        .version(shadowsocks::VERSION)
        .about("A DNS proxy that helps you bypass firewalls.")
        .arg(
            Arg::with_name("VERBOSE")
                .short("v")
                .multiple(true)
                .help("Set the level of debug"),
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
            Arg::with_name("REMOTE_DNS")
                .long("remote-dns")
                .takes_value(true)
                .help("Remote DNS server, default is 8.8.8.8:53"),
        )
        .get_matches();

    let without_time = matches.is_present("LOG_WITHOUT_TIME");
    let debug_level = matches.occurrences_of("VERBOSE");

    logging::init(without_time, debug_level, "ssdns");

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

    if let Some(dns) = matches.value_of("REMOTE_DNS") {
        let dns_addr = dns
            .parse::<SocketAddr>()
            .expect("`remote-dns` is not a valid SocketAddr, must be IP:Port");
        config.remote_dns = Some(dns_addr);
    }

    info!("ShadowSocks DNS {}", shadowsocks::VERSION);

    debug!("Config: {:?}", config);

    let mut runtime = Runtime::new().expect("Creating runtime");

    let result = runtime.block_on(run_dns(config));

    runtime.shutdown_now().wait().unwrap();

    panic!("Server exited unexpectly with result: {:?}", result);
}
