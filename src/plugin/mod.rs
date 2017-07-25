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

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};

use subprocess::Popen;
use subprocess::Result as PopenResult;

use config::{Config, ServerAddr};

mod ss_plugin;
mod obfs_proxy;

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

/// Plugin holder
#[derive(Debug)]
pub struct Plugin {
    addr: ServerAddr,
    process: Popen,
}

impl Plugin {
    /// Get address of the plugin
    pub fn addr(&self) -> &ServerAddr {
        &self.addr
    }
}

impl Drop for Plugin {
    fn drop(&mut self) {
        let _ = self.process.terminate();
    }
}

/// Launch plugins in config
pub fn launch_plugin(config: &mut Config, mode: PluginMode) -> io::Result<Vec<Plugin>> {
    let mut plugins = Vec::new();

    for svr in &mut config.server {
        let mut svr_addr_opt = None;

        if let Some(c) = svr.plugin() {
            let loop_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
            let local_addr = SocketAddr::new(loop_ip, get_local_port()?);

            let svr_addr = match start_plugin(c, svr.addr(), &local_addr, mode) {
                Err(err) => {
                    panic!("Failed to start plugin \"{}\", err: {}", c.plugin, err);
                }
                Ok(p) => {
                    let svr_addr = ServerAddr::SocketAddr(local_addr);
                    plugins.push(Plugin {
                                     addr: svr_addr.clone(),
                                     process: p,
                                 });

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
            svr.set_addr(svr_addr);
        }
    }

    Ok(plugins)
}

fn start_plugin(plugin: &PluginConfig,
                remote: &ServerAddr,
                local: &SocketAddr,
                mode: PluginMode)
                -> PopenResult<Popen> {
    if plugin.plugin == "obfsproxy" {
        obfs_proxy::start_plugin(plugin, remote, local, mode)
    } else {
        ss_plugin::start_plugin(plugin, remote, local, mode)
    }
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
