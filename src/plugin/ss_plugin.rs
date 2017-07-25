use std::net::SocketAddr;

use subprocess::{Exec, NullFile, Popen};
use subprocess::Result as PopenResult;

use config::ServerAddr;

use super::{PluginConfig, PluginMode};

pub fn start_plugin(plugin: &PluginConfig,
                    remote: &ServerAddr,
                    local: &SocketAddr,
                    _mode: PluginMode)
                    -> PopenResult<Popen> {
    trace!("Start plugin \"{:?}\" remote: {}, local: {}", plugin, remote, local);

    let mut exec = Exec::cmd(&plugin.plugin)
        .env("SS_REMOTE_HOST", remote.host())
        .env("SS_REMOTE_PORT", remote.port().to_string())
        .env("SS_LOCAL_HOST", local.ip().to_string())
        .env("SS_LOCAL_PORT", local.port().to_string())
        .stdin(NullFile);

    if let Some(ref opt) = plugin.plugin_opt {
        exec = exec.env("SS_PLUGIN_OPTIONS", opt);
    }

    exec.popen()
}
