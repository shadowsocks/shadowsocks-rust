//! This is a binary running in the server environment
//!
//! You have to provide all needed configuration attributes via command line parameters,
//! or you could specify a configuration file. The format of configuration file is defined
//! in mod `config`.
//!
//! *It should be notice that the extented configuration file is not suitable for the server
//! side.*

use std::net::{IpAddr, SocketAddr};

use clap::{Arg, clap_app};
use futures::future::{self, Either};
use log::{error, info};
use tokio::{self, runtime::Builder};

use shadowsocks::{
    acl::AccessControl,
    crypto::CipherType,
    plugin::PluginConfig,
    run_server,
    Config,
    ConfigType,
    ManagerAddr,
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
        (@arg BIND_ADDR: -b --("bind-addr") +takes_value "Bind address, outbound socket will bind this address")
        (@arg SERVER_ADDR: -s --("server-addr") +takes_value requires[PASSWORD ENCRYPT_METHOD] "Server address")
        (@arg PASSWORD: -k --password +takes_value requires[SERVER_ADDR ENCRYPT_METHOD] "Password")
        (@arg PLUGIN: --plugin +takes_value "Enable SIP003 plugin")
        (@arg PLUGIN_OPT: --("plugin-opts") +takes_value requires[PLUGIN] "Set SIP003 plugin options")
        (@group SERVER_CONFIG =>
            (@attributes +required ... arg[CONFIG SERVER_ADDR URL])
        )
        (@arg MANAGER_ADDRESS: --("manager-address") +takes_value "ShadowSocks Manager (ssmgr) address, could be \"IP:Port\", \"Domain:Port\" or \"/path/to/unix.sock\"")
        (@arg NO_DELAY: --("no-delay") !takes_value "Set no-delay option for socket")
        (@arg NOFILE: -n --nofile +takes_value "Set RLIMIT_NOFILE with both soft and hard limit (only for *nix systems)")
        (@arg ACL: --acl +takes_value "Path to ACL (Access Control List)")
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
    logging::init(debug_level, "ssserver");

    let mut config = match matches.value_of("CONFIG") {
        Some(cpath) => match Config::load_from_file(cpath, ConfigType::Server) {
            Ok(cfg) => cfg,
            Err(err) => {
                error!("{:?}", err);
                return;
            }
        },
        None => Config::new(ConfigType::Server),
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

    if let Some(bind_addr) = matches.value_of("BIND_ADDR") {
        let bind_addr = match bind_addr.parse::<IpAddr>() {
            Ok(ip) => ServerAddr::from(SocketAddr::new(ip, 0)),
            Err(..) => ServerAddr::from((bind_addr, 0)),
        };

        config.local_addr = Some(bind_addr);
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
        config.manager_addr = Some(
            m.parse::<ManagerAddr>()
                .expect("\"IP:Port\", \"Domain:Port\" or \"/path/to/unix.sock\" for `manager_address`"),
        );
    }

    if let Some(nofile) = matches.value_of("NOFILE") {
        config.nofile = Some(nofile.parse::<u64>().expect("an unsigned integer for `nofile`"));
    }

    if let Some(acl_file) = matches.value_of("ACL") {
        let acl = AccessControl::load_from_file(acl_file).expect("load ACL file");
        config.acl = Some(acl);
    }

    if matches.is_present("IPV6_FIRST") {
        config.ipv6_first = true;
    }

    // DONE READING options

    if config.server.is_empty() {
        eprintln!(
            "missing proxy servers, consider specifying it by \
             --server-addr, --encrypt-method, --password command line option, \
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
        let server = run_server(config, rt_handle);

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
