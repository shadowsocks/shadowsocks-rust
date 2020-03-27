//! This is a binary running in the local environment
//!
//! You have to provide all needed configuration attributes via command line parameters,
//! or you could specify a configuration file. The format of configuration file is defined
//! in mod `config`.

use clap::{Arg, clap_app};
use futures::future::{self, Either};
use log::{error, info};
use tokio::{self, runtime::Builder};

use shadowsocks::{
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

fn main() {
    let available_ciphers = CipherType::available_ciphers();

    let app = clap_app!(shadowsocks =>
        (version: shadowsocks::VERSION)
        (about: "A fast tunnel proxy that helps you bypass firewalls.")
        (@arg VERBOSE: -v ... "Set the level of debug")
        (@arg UDP_ONLY: -u conflicts_with[TCP_AND_UDP] "Server mode UDP_ONLY")
        (@arg TCP_AND_UDP: -U conflicts_with[UDP_ONLY] "Server mode TCP_AND_UDP")
        (@arg CONFIG: -c --config +takes_value "Specify config file")
        (@arg LOCAL_ADDR: -b --("local-addr") +takes_value "Local address, listen only to this address if specified")
        (@arg FORWARD_ADDR: -f --("foward-addr") +takes_value +required "Forward address, forward to this address")
        (@arg SERVER_ADDR: -s --("server-addr") +takes_value requires[PASSWORD ENCRYPT_METHOD] "Server address")
        (@arg PASSWORD: -k --password +takes_value requires[SERVER_ADDR ENCRYPT_METHOD] "Password")
        (@arg PLUGIN: --plugin +takes_value "Enable SIP003 plugin")
        (@arg PLUGIN_OPT: --("plugin-opts") +takes_value requires[PLUGIN] "Set SIP003 plugin options")
        (@arg URL: --("server-url") +takes_value "Server address in SIP002 URL")
        (@group SERVER_CONFIG =>
            (@attributes +required ... arg[CONFIG SERVER_ADDR URL])
        )
        (@group LOCAL_CONFIG =>
            (@attributes +required ... arg[CONFIG LOCAL_ADDR])
        )
        (@arg NO_DELAY: --("no-delay") !takes_value "Set no-delay option for socket")
        (@arg NOFILE: -n --nofile +takes_value "Set RLIMIT_NOFILE with both soft and hard limit (only for *nix systems)")
    );


    let matches = app
        .arg(
            Arg::with_name("ENCRYPT_METHOD")
                .short("m")
                .long("encrypt-method")
                .takes_value(true)
                .possible_values(&available_ciphers)
                .help("Encryption method")
                .requires_all(&["SERVER_ADDR", "PASSWORD"]),
        )
        .arg(
            Arg::with_name("IPV6_FIRST")
                .short("6")
                .help("Resovle hostname to IPv6 address first"),
        )
        .get_matches();

    drop(available_ciphers);

    let debug_level = matches.occurrences_of("VERBOSE");
    logging::init(debug_level, "sstunnel");

    let mut config = match matches.value_of("CONFIG") {
        Some(cpath) => match Config::load_from_file(cpath, ConfigType::TunnelLocal) {
            Ok(cfg) => cfg,
            Err(err) => {
                error!("{:?}", err);
                return;
            }
        },
        None => Config::new(ConfigType::TunnelLocal),
    };

    if let Some(svr_addr) = matches.value_of("SERVER_ADDR") {
        let password = matches.value_of("PASSWORD").expect("password");
        let method = matches.value_of("ENCRYPT_METHOD").expect("encrypt-method");

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

    if let Some(url) = matches.value_of("URL") {
        let svr_addr = url.parse::<ServerConfig>().expect("parse `url`");
        config.server.push(svr_addr);
    }

    if let Some(local_addr) = matches.value_of("LOCAL_ADDR") {
        let local_addr = local_addr
            .parse::<ServerAddr>()
            .expect("`local-addr` should be \"IP:Port\" or \"Domain:Port\"");

        config.local_addr = Some(local_addr);
    };

    if let Some(url) = matches.value_of("FORWARD_ADDR") {
        let forward_addr = url.parse::<Address>().expect("parse `url`");

        config.forward = Some(forward_addr);
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
