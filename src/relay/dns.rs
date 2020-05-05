//! DNS relay

use std::io::{self, ErrorKind};

use futures::{future::select_all, FutureExt};
use log::{debug, error, trace, warn};
use tokio::runtime::Handle;

use crate::{
    config::{Config, ConfigType},
    context::{Context, ServerState},
    plugin::{PluginMode, Plugins},
    relay::{dnsrelay::run as run_dns, utils::set_nofile},
};

/// DNS relay server running under local environment.
pub async fn run(mut config: Config, rt: Handle) -> io::Result<()> {
    trace!("initializing local server with {:?}", config);

    assert_eq!(config.config_type, ConfigType::DnsLocal);

    if let Some(nofile) = config.nofile {
        debug!("setting RLIMIT_NOFILE to {}", nofile);
        if let Err(err) = set_nofile(nofile) {
            match err.kind() {
                ErrorKind::PermissionDenied => {
                    warn!("insufficient permission to change RLIMIT_NOFILE, try to restart as root user");
                }
                ErrorKind::InvalidInput => {
                    warn!("invalid `nofile` value {}, decrease it and try again", nofile);
                }
                _ => {
                    error!("failed to set RLIMIT_NOFILE with value {}, error: {}", nofile, err);
                }
            }
            return Err(err);
        }
    }

    // Create a context containing a DNS resolver and server running state flag.
    let state = ServerState::new_shared(&config, rt).await;

    let mut vf = Vec::new();

    let context = if config.mode.enable_tcp() {
        // Run TCP local server if
        //
        //  1. Enabled TCP relay
        //  2. Not in tunnel mode. (Socks5 UDP relay requires TCP port enabled)

        if config.has_server_plugins() {
            let plugins = Plugins::launch_plugins(&mut config, PluginMode::Client)?;

            // Wait until all plugins actually start
            // Some plugins require quite a lot bootstrap time
            Plugins::check_plugins_started(&config).await?;

            vf.push(plugins.boxed());
        }

        Context::new_shared(config, state)
    } else {
        Context::new_shared(config, state)
    };

    let server = run_dns(context.clone());
    vf.push(server.boxed());

    let (res, ..) = select_all(vf.into_iter()).await;
    error!("one of servers exited unexpectly, result: {:?}", res);

    // Tells all detached tasks to exit
    context.set_server_stopped();

    Err(io::Error::new(io::ErrorKind::Other, "server exited unexpectly"))
}
