use super::{PluginConfig, PluginMode};
use crate::config::ServerAddr;
use std::{
    net::SocketAddr,
    process::{Command, Stdio},
};

pub fn plugin_cmd(plugin: &PluginConfig, remote: &ServerAddr, local: &SocketAddr, _mode: PluginMode) -> Command {
    trace!("Start plugin \"{:?}\" remote: {}, local: {}", plugin, remote, local);

    let mut cmd = Command::new(&plugin.plugin);
    cmd.env("SS_REMOTE_HOST", remote.host())
        .env("SS_REMOTE_PORT", remote.port().to_string())
        .env("SS_LOCAL_HOST", local.ip().to_string())
        .env("SS_LOCAL_PORT", local.port().to_string())
        .stdin(Stdio::null());

    if let Some(ref opt) = plugin.plugin_opt {
        cmd.env("SS_PLUGIN_OPTIONS", opt);
    }

    cmd
}
