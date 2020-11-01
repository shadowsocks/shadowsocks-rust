//! Server side

use std::{
    io::{self, ErrorKind},
    time::Duration,
};

use futures::future::{select_all, FutureExt};
use log::{debug, error, trace, warn};
use tokio::time;

use crate::{
    config::Config,
    context::{Context, ServerState, SharedContext, SharedServerState},
    plugin::{PluginMode, Plugins},
    relay::{
        flow::{MultiServerFlowStatistic, SharedMultiServerFlowStatistic},
        manager::ManagerDatagram,
        tcprelay::server::run as run_tcp,
        udprelay::server::run as run_udp,
        utils::set_nofile,
    },
};

/// Runs Relay server on server side.
#[inline]
pub async fn run(config: Config) -> io::Result<()> {
    // Create a context containing a DNS resolver and server running state flag.
    let server_state = ServerState::new_shared(&config).await;

    // Create statistics for multiple servers
    //
    // This is for statistic purpose for [Manage Multiple Users](https://github.com/shadowsocks/shadowsocks/wiki/Manage-Multiple-Users) APIs
    let flow_stat = MultiServerFlowStatistic::new_shared(&config);

    run_with(config, flow_stat, server_state).await
}

pub(crate) async fn run_with(
    mut config: Config,
    flow_stat: SharedMultiServerFlowStatistic,
    server_stat: SharedServerState,
) -> io::Result<()> {
    trace!("initializing server with {:?}", config);

    assert!(config.config_type.is_server());

    if let Some(nofile) = config.nofile {
        debug!("setting RLIMIT_NOFILE to {}", nofile);
        if let Err(err) = set_nofile(nofile) {
            match err.kind() {
                ErrorKind::PermissionDenied => {
                    warn!("insufficient permission to change `nofile`, try to restart as root user");
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

    let mode = config.mode;

    let mut vf = Vec::new();

    let context = if mode.enable_tcp() {
        if config.has_server_plugins() {
            let plugins = Plugins::launch_plugins(&mut config, PluginMode::Server).await?;
            vf.push(plugins.boxed());
        }

        let context = Context::new_with_state_shared(config, server_stat);

        let tcp_fut = run_tcp(context.clone(), flow_stat.clone());
        vf.push(tcp_fut.boxed());

        context
    } else {
        Context::new_with_state_shared(config, server_stat)
    };

    if mode.enable_udp() {
        // Run UDP relay before starting plugins
        // Because plugins doesn't support UDP relay
        let udp_fut = run_udp(context.clone(), flow_stat.clone());
        vf.push(udp_fut.boxed());
    }

    // If specified manager-address, reports transmission statistic to it
    //
    // Dont do that if server is created by manager
    if context.config().manager.is_some() {
        let report_fut = manager_report_task(context.clone(), flow_stat);
        vf.push(report_fut.boxed());
    }

    let (res, ..) = select_all(vf.into_iter()).await;
    error!("one of servers exited unexpectly, result: {:?}", res);

    // Tells all detached tasks to exit
    context.set_server_stopped();

    Err(io::Error::new(io::ErrorKind::Other, "server exited unexpectly"))
}

async fn manager_report_task(context: SharedContext, flow_stat: SharedMultiServerFlowStatistic) -> io::Result<()> {
    let manager_config = context.config().manager.as_ref().unwrap();
    let manager_addr = &manager_config.addr;
    let mut socket = ManagerDatagram::bind_for(manager_addr).await?;

    while context.server_running() {
        // For each servers, send "stat" command to manager
        //
        // This is for compatible with managers that replies on "stat" command
        // Ref: https://github.com/shadowsocks/shadowsocks/wiki/Manage-Multiple-Users
        //
        // If you are using manager in this project, this is not required.
        for svr_cfg in &context.config().server {
            let port = svr_cfg.addr().port();

            if let Some(ref fstat) = flow_stat.get(port) {
                let stat = format!("stat: {{\"{}\":{}}}", port, fstat.trans_stat());

                match socket.send_to_manager(stat.as_bytes(), &context, &manager_addr).await {
                    Ok(..) => {
                        trace!(
                            "sent {} for server \"{}\" to manger \"{}\"",
                            stat,
                            svr_cfg.addr(),
                            manager_addr
                        );
                    }
                    Err(err) => {
                        debug!(
                            "failed to send {} for server \"{}\" to manager \"{}\", error: {}",
                            stat,
                            svr_cfg.addr(),
                            manager_addr,
                            err
                        );
                    }
                }
            }
        }

        // Report every 10 seconds
        time::delay_for(Duration::from_secs(10)).await;
    }

    Ok(())
}
