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

use std::{
    future::Future,
    io::{self, Error, ErrorKind},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures::future;
use log::{debug, error, info, trace};
use tokio::{net::TcpStream, process::Child, time};

use crate::config::{Config, ServerAddr};

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

/// Started plugins' subprocesses carrier
pub struct Plugins {
    plugins: Vec<Child>,
}

impl Drop for Plugins {
    #[cfg(not(unix))]
    fn drop(&mut self) {
        for plugin in &mut self.plugins {
            debug!("killing plugin process {}", plugin.id());
            let _ = plugin.kill();
        }
    }

    #[cfg(unix)]
    fn drop(&mut self) {
        // Step.1 Send SIGTERM to let them exit gracefully
        for plugin in &mut self.plugins {
            debug!("terminating plugin process {}", plugin.id());

            unsafe {
                let ret = libc::kill(plugin.id() as libc::pid_t, libc::SIGTERM);
                if ret != 0 {
                    let err = io::Error::last_os_error();
                    error!("terminating plugin process {}, error: {}", plugin.id(), err);
                }
            }
        }

        // Step.2 Sit and tight. Let plugins to exit gracefully
        std::thread::sleep(Duration::from_millis(500));

        // Step.3 SIGKILL. Kill all of them forcibly
        for plugin in &mut self.plugins {
            if let Ok(..) = plugin.kill() {
                debug!("killed plugin process {}", plugin.id());
            }
        }
    }
}

impl Plugins {
    /// Launch plugins in configuration.
    ///
    /// Will modify servers' listen addresses to plugins' listen addresses.
    pub fn launch_plugins(config: &mut Config, mode: PluginMode) -> io::Result<Plugins> {
        let mut plugins = Vec::new();

        for svr in &mut config.server {
            let mut svr_addr_opt = None;

            if let Some(c) = svr.plugin() {
                let loop_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
                let local_addr = SocketAddr::new(loop_ip, get_local_port()?);

                let svr_addr = match start_plugin(c, svr.addr(), &local_addr, mode) {
                    Err(err) => {
                        error!(
                            "failed to start plugin \"{}\" for server {}, err: {}",
                            c.plugin,
                            svr.addr(),
                            err
                        );
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
                    PluginMode::Client => info!("started plugin \"{}\" on {} <-> {}", c.plugin, local_addr, svr.addr()),
                    PluginMode::Server => info!("started plugin \"{}\" on {} <-> {}", c.plugin, svr.addr(), local_addr),
                }

                svr_addr_opt = Some(svr_addr); // Fuck borrow checker
            }

            if let Some(svr_addr) = svr_addr_opt {
                svr.set_plugin_addr(svr_addr);
            }
        }

        if plugins.is_empty() {
            panic!("didn't find any plugins to start");
        }

        Ok(Plugins { plugins })
    }

    /// Check plugin started
    ///
    /// This future won't resolve until all plugins are started
    pub async fn check_plugins_started(config: &Config) -> io::Result<()> {
        if !config.has_server_plugins() {
            return Ok(());
        }

        let mut v = Vec::new();

        for svr in &config.server {
            if let Some(ref saddr) = svr.plugin_addr() {
                let addr = match *saddr {
                    ServerAddr::SocketAddr(a) => a,
                    ServerAddr::DomainName(..) => unreachable!("impossible, plugin_addr shouldn't be domain name"),
                };

                v.push(async move {
                    // Try to connect plugin 10 times (nearly 2 seconds)
                    for r in 0..10 {
                        if let Ok(..) = TcpStream::connect(&addr).await {
                            debug!(
                                "plugin \"{}\" for {} listening on {} is started",
                                svr.plugin().as_ref().unwrap().plugin,
                                svr.addr(),
                                addr
                            );

                            return Ok(());
                        }

                        trace!(
                            "plugin \"{}\" for {} listening on {} isn't started yet, tried {} times",
                            svr.plugin().as_ref().unwrap().plugin,
                            svr.addr(),
                            addr,
                            r
                        );

                        time::delay_for(Duration::from_millis(200)).await;
                    }

                    let err = Error::new(ErrorKind::Other, format!("failed to connect plugin \"{}\"", addr));
                    Err(err)
                });
            }
        }

        future::try_join_all(v).await.map(|_| ())
    }
}

impl Future for Plugins {
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        for p in &mut self.plugins {
            match Pin::new(p).poll(cx) {
                Poll::Ready(Ok(exit_status)) => {
                    let msg = format!("plugin exited unexpectedly with {}", exit_status);
                    return Poll::Ready(Err(Error::new(io::ErrorKind::Other, msg)));
                }
                Poll::Ready(Err(err)) => {
                    error!("error while waiting for plugin subprocess: {}", err);
                    return Poll::Ready(Err(err));
                }
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }
}

fn start_plugin(plugin: &PluginConfig, remote: &ServerAddr, local: &SocketAddr, mode: PluginMode) -> io::Result<Child> {
    let mut cmd = if plugin.plugin == "obfsproxy" {
        obfs_proxy::plugin_cmd(plugin, remote, local, mode)
    } else {
        ss_plugin::plugin_cmd(plugin, remote, local, mode)
    };
    cmd.spawn()
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
