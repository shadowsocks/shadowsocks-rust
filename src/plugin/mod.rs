//! Plugin (SIP003)
//!
//! ```plain
//! +------------+                    +---------------------------+
//! |  SS Client +-- Local Loopback --+  Plugin Client (Tunnel)   +--+
//! +------------+                    +---------------------------+  |
//!                                                                  |
//!             Public Internet (Obfuscated/Transformed traffic) ==> |
//!                                                                  |
//! +------------+                    +---------------------------+  |
//! |  SS Server +-- Local Loopback --+  Plugin Server (Tunnel)   +--+
//! +------------+                    +---------------------------+
//! ```

use crate::config::{Config, ServerAddr};
use futures::{
    future::pending,
    stream::{FuturesUnordered, StreamExt},
};
use log::{error, info};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
};
use tokio_process::{Child, CommandExt};

mod obfs_proxy;
mod ss_plugin;

/// Config for plugin
#[derive(Debug, Clone)]
pub struct PluginConfig {
    pub plugin: String,
    pub plugin_opt: Option<String>,
}

/// Mode of Plugin
#[derive(Debug, Clone, Copy)]
pub enum PluginMode {
    Server,
    Client,
}

/// Launch plugins in config. Returns a future that completes when any plugin terminates
/// or there were an error in watching the subprocess. Returns `None` if no plugins
/// were launched.
pub async fn launch_plugins(config: &mut Config, mode: PluginMode) -> io::Result<()> {
    let mut plugins = FuturesUnordered::new();

    for svr in &mut config.server {
        let mut svr_addr_opt = None;

        if let Some(c) = svr.plugin() {
            let loop_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
            let local_addr = SocketAddr::new(loop_ip, get_local_port()?);

            let svr_addr = match start_plugin(c, svr.addr(), &local_addr, mode) {
                Err(err) => {
                    error!("Failed to start plugin \"{}\", err: {}", c.plugin, err);
                    return Err(err);
                }
                Ok(process) => {
                    let svr_addr = ServerAddr::SocketAddr(local_addr);
                    plugins.push(process);

                    // Replace addr with plugin
                    svr_addr
                }
            };

            match mode {
                PluginMode::Client => info!("Started plugin \"{}\" on {} <-> {}", c.plugin, local_addr, svr.addr()),
                PluginMode::Server => info!("Started plugin \"{}\" on {} <-> {}", c.plugin, svr.addr(), local_addr),
            }

            svr_addr_opt = Some(svr_addr); // Fuck borrow checker
        }

        if let Some(svr_addr) = svr_addr_opt {
            svr.set_plugin_addr(svr_addr);
        }
    }

    if plugins.is_empty() {
        panic!("Didn't find any plugins to start");
    } else {
        // Turn the vector of `Child` futures into a single future that
        // completes with an error if any of them exits or waiting for it
        // fails. When this future completes, the remaining `Child`ren will be
        // dropped and as a result the rest of the plugins will be killed
        // automatically.

        match plugins.into_future().await {
            (Some(Ok(first_plugin_exit_status)), _) => {
                let msg = format!("Plugin exited unexpectedly with {}", first_plugin_exit_status);
                Err(io::Error::new(io::ErrorKind::Other, msg))
            }
            (Some(Err(first_plugin_error)), _) => {
                error!("Error while waiting for plugin subprocess: {}", first_plugin_error);
                Err(first_plugin_error)
            }
            _ => unreachable!(),
        }
    }
}

fn start_plugin(plugin: &PluginConfig, remote: &ServerAddr, local: &SocketAddr, mode: PluginMode) -> io::Result<Child> {
    let mut cmd = if plugin.plugin == "obfsproxy" {
        obfs_proxy::plugin_cmd(plugin, remote, local, mode)
    } else {
        ss_plugin::plugin_cmd(plugin, remote, local, mode)
    };
    cmd.spawn_async()
}

fn get_local_port() -> io::Result<u16> {
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0))?;
    let addr = listener.local_addr()?;
    Ok(addr.port())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn generate_random_port() {
        let port = get_local_port().unwrap();
        println!("{:?}", port);
    }
}
