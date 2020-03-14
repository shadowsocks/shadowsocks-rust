use super::{PluginConfig, PluginMode};
use crate::config::ServerAddr;
use log::trace;
use std::{net::SocketAddr, process::Stdio};
use tokio::process::Command;

pub fn plugin_cmd(plugin: &PluginConfig, remote: &ServerAddr, local: &SocketAddr, _mode: PluginMode) -> Command {
    trace!(
        "Starting plugin \"{}\", opt: {:?} remote: {}, local: {}",
        plugin.plugin,
        plugin.plugin_opt,
        remote,
        local
    );

    let mut cmd = Command::new(&plugin.plugin);
    cmd.env("SS_REMOTE_HOST", remote.host())
        .env("SS_REMOTE_PORT", remote.port().to_string())
        .env("SS_LOCAL_HOST", local.ip().to_string())
        .env("SS_LOCAL_PORT", local.port().to_string())
        .stdin(Stdio::null());

    if let Some(ref opt) = plugin.plugin_opt {
        cmd.env("SS_PLUGIN_OPTIONS", opt);
        #[cfg(target_os = "android")]
        {
            // Add VPN flags to the commandline as well
            if opt.contains(";V") {
                cmd.arg("-V");
            }
        }
    }

    cmd
}
