//! Local side

use std::{
    io::{self, ErrorKind},
    sync::Arc,
};

use futures::{future::select_all, FutureExt};
use log::{debug, error, trace, warn};
use tokio::runtime::Handle;

use crate::{
    config::{Config, ConfigType},
    context::{Context, ServerState},
    plugin::{PluginMode, Plugins},
    relay::{tcprelay::local::run as run_tcp, udprelay::local::run as run_udp, utils::set_nofile},
};

/// Relay server running under local environment.
pub async fn run(config: Config, rt: Handle) -> io::Result<()> {
    trace!("{:?}", config);
    assert!(config.config_type.is_local());

    if let Some(nofile) = config.nofile {
        debug!("Setting RLIMIT_NOFILE to {}", nofile);
        if let Err(err) = set_nofile(nofile) {
            match err.kind() {
                ErrorKind::PermissionDenied => {
                    warn!("Insufficient permission to change RLIMIT_NOFILE, try to restart as root user");
                }
                ErrorKind::InvalidInput => {
                    warn!("Invalid `nofile` value {}, decrease it and try again", nofile);
                }
                _ => {
                    error!("Failed to set RLIMIT_NOFILE with value {}, error: {}", nofile, err);
                }
            }
            return Err(err);
        }
    }

    let config_type = config.config_type;
    let mode = config.mode;

    // Create a context containing a DNS resolver and server running state flag.
    let state = ServerState::new(&config, rt).await?;
    let mut context = Context::new_shared(config, state.clone());

    let mut vf = Vec::new();

    let enable_tcp = match config_type {
        // Socks5 always true, because UDP associate command also requires a TCP connection
        ConfigType::Socks5Local => true,
        // Tunnel mode controlled by this flag
        ConfigType::TunnelLocal => mode.enable_tcp(),
        // HTTP must be TCP
        ConfigType::HttpLocal => true,
        // Redir mode controlled by this flag
        ConfigType::RedirLocal => mode.enable_tcp(),

        _ => false,
    };

    if enable_tcp {
        // Run TCP local server if
        //
        //  1. Enabled TCP relay
        //  2. Not in tunnel mode. (Socks5 UDP relay requires TCP port enabled)

        if context.config().has_server_plugins() {
            let context = Arc::make_mut(&mut context);
            let plugins = Plugins::launch_plugins(context.config_mut(), PluginMode::Client)?;

            // Wait until all plugins actually start
            // Some plugins require quite a lot bootstrap time
            Plugins::check_plugins_started(context.config()).await?;

            vf.push(plugins.into_future().boxed());
        }

        let tcp_fut = run_tcp(context.clone());
        vf.push(tcp_fut.boxed());
    }

    let enable_udp = match config_type {
        ConfigType::Socks5Local | ConfigType::TunnelLocal | ConfigType::RedirLocal => mode.enable_udp(),
        _ => false,
    };

    if enable_udp {
        // Run UDP relay before starting plugins
        // Because plugins doesn't support UDP relay
        let udp_fut = run_udp(context);
        vf.push(udp_fut.boxed());
    }

    let (res, ..) = select_all(vf.into_iter()).await;
    error!("one of servers exited unexpectly, result: {:?}", res);

    // Tells all detached tasks to exit
    state.server_stopped();

    Err(io::Error::new(io::ErrorKind::Other, "server exited unexpectly"))
}
