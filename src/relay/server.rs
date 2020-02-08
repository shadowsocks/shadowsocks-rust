//! Server side

use std::io::{self, ErrorKind};

use futures::future::{select_all, FutureExt};
use log::{debug, error, trace, warn};
use tokio::runtime::Handle;

use crate::{
    config::Config,
    context::{Context, ServerState, SharedServerState},
    plugin::{PluginMode, Plugins},
    relay::{
        flow::{ServerFlowStatistic, SharedServerFlowStatistic},
        tcprelay::server::run as run_tcp,
        udprelay::server::run as run_udp,
        utils::set_nofile,
    },
};

/// Runs Relay server on server side.
#[inline]
pub async fn run(config: Config, rt: Handle) -> io::Result<()> {
    // Create a context containing a DNS resolver and server running state flag.
    let server_state = ServerState::new_shared(&config, rt).await?;

    // Create a server flow statistic, which is not very useful in standalone server
    let flow_stat = ServerFlowStatistic::new_shared();

    run_with(config, flow_stat, server_state).await
}

pub(crate) async fn run_with(
    mut config: Config,
    flow_stat: SharedServerFlowStatistic,
    server_stat: SharedServerState,
) -> io::Result<()> {
    trace!("RUN Server {:?}", config);
    assert!(config.config_type.is_server());

    if let Some(nofile) = config.nofile {
        debug!("Setting RLIMIT_NOFILE to {}", nofile);
        if let Err(err) = set_nofile(nofile) {
            match err.kind() {
                ErrorKind::PermissionDenied => {
                    warn!("Insufficient permission to change `nofile`, try to restart as root user");
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

    let mode = config.mode;

    let mut vf = Vec::new();

    let context = if mode.enable_tcp() {
        if config.has_server_plugins() {
            let plugins = Plugins::launch_plugins(&mut config, PluginMode::Client)?;
            vf.push(plugins.into_future().boxed());
        }

        let context = Context::new_shared(config, server_stat);

        let tcp_fut = run_tcp(context.clone(), flow_stat.clone());
        vf.push(tcp_fut.boxed());

        context
    } else {
        Context::new_shared(config, server_stat)
    };

    if mode.enable_udp() {
        // Run UDP relay before starting plugins
        // Because plugins doesn't support UDP relay
        let udp_fut = run_udp(context.clone(), flow_stat.clone());
        vf.push(udp_fut.boxed());
    }

    let (res, ..) = select_all(vf.into_iter()).await;
    error!("one of servers exited unexpectly, result: {:?}", res);

    // Tells all detached tasks to exit
    context.server_stopped();

    Err(io::Error::new(io::ErrorKind::Other, "server exited unexpectly"))
}
