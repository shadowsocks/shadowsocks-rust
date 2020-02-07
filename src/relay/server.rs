//! Server side

use std::{
    future::Future,
    io::{self, ErrorKind},
    sync::Arc,
};

use futures::future::{select_all, FutureExt};
use log::{debug, error, trace, warn};
use tokio::runtime::Handle;

use crate::{
    config::Config,
    context::{Context, ServerState},
    plugin::{PluginMode, Plugins},
    relay::{
        flow::{ServerFlowStatistic, SharedServerFlowStatistic},
        tcprelay::server::run as run_tcp,
        udprelay::server::run as run_udp,
        utils::set_nofile,
    },
};

/// Runs Relay server on server side.
pub async fn run(config: Config, rt: Handle) -> io::Result<()> {
    let (f, _) = create_server(config, rt).await?;
    f.await
}

/// Create a Relay server running on server side.
pub async fn create_server(
    config: Config,
    rt: Handle,
) -> io::Result<(impl Future<Output = io::Result<()>>, SharedServerFlowStatistic)> {
    trace!("{:?}", config);
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

    // Create a context containing a DNS resolver and server running state flag.
    let state = ServerState::new(&config, rt).await?;
    let mut context = Context::new_shared(config, state.clone());

    let mode = context.config().mode;
    let flow_stat = ServerFlowStatistic::new_shared();

    let mut vf = Vec::new();

    if mode.enable_tcp() {
        if context.config().has_server_plugins() {
            let context = Arc::make_mut(&mut context);
            let plugins = Plugins::launch_plugins(context.config_mut(), PluginMode::Client)?;
            vf.push(plugins.into_future().boxed());
        }

        let tcp_fut = run_tcp(context.clone(), flow_stat.clone());
        vf.push(tcp_fut.boxed());
    }

    if mode.enable_udp() {
        // Run UDP relay before starting plugins
        // Because plugins doesn't support UDP relay
        let udp_fut = run_udp(context, flow_stat.clone());
        vf.push(udp_fut.boxed());
    }

    let svr = async move {
        let (res, ..) = select_all(vf.into_iter()).await;
        error!("one of servers exited unexpectly, result: {:?}", res);

        // Tells all detached tasks to exit
        state.server_stopped();

        Err(io::Error::new(io::ErrorKind::Other, "server exited unexpectly"))
    };

    Ok((svr, flow_stat))
}
