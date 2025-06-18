//! Online Config (SIP008)
//!
//! Online Configuration Delivery URL (https://shadowsocks.org/doc/sip008.html)

use std::{
    collections::HashSet,
    io,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{
    config::{Config, ConfigType},
    local::{context::ServiceContext, http::HttpClient, loadbalancing::PingBalancer},
};

use http::StatusCode;
use log::{debug, error, trace, warn};
use mime::Mime;
use shadowsocks::config::ServerSource;
use tokio::time;

use self::content_encoding::{ContentEncoding, read_body};

mod content_encoding;

/// OnlineConfigService builder pattern
pub struct OnlineConfigServiceBuilder {
    context: Arc<ServiceContext>,
    config_url: String,
    balancer: PingBalancer,
    config_update_interval: Duration,
    allowed_plugins: Option<HashSet<String>>,
}

impl OnlineConfigServiceBuilder {
    /// Create a Builder
    pub fn new(context: Arc<ServiceContext>, config_url: String, balancer: PingBalancer) -> Self {
        Self {
            context,
            config_url,
            balancer,
            config_update_interval: Duration::from_secs(3600),
            allowed_plugins: None,
        }
    }

    /// Set update interval. Default is 3600s
    pub fn set_update_interval(&mut self, update_interval: Duration) {
        self.config_update_interval = update_interval;
    }

    /// Allowed plugins (whitelist) from SIP008 server
    pub fn set_allowed_plugins<V, S>(&mut self, allowed_plugins: V)
    where
        V: Iterator<Item = S>,
        S: Into<String>,
    {
        let mut allowed_plugins_set = HashSet::new();
        for plugin in allowed_plugins {
            allowed_plugins_set.insert(plugin.into());
        }
        self.allowed_plugins = Some(allowed_plugins_set);
    }

    /// Build OnlineConfigService
    pub async fn build(self) -> io::Result<OnlineConfigService> {
        let mut service = OnlineConfigService {
            context: self.context,
            http_client: HttpClient::new(),
            config_url: self.config_url,
            config_update_interval: self.config_update_interval,
            balancer: self.balancer,
            allowed_plugins: self.allowed_plugins,
        };

        // Run once after creation.
        service.run_once().await?;

        Ok(service)
    }
}

pub struct OnlineConfigService {
    context: Arc<ServiceContext>,
    http_client: HttpClient<String>,
    config_url: String,
    config_update_interval: Duration,
    balancer: PingBalancer,
    allowed_plugins: Option<HashSet<String>>,
}

impl OnlineConfigService {
    async fn run_once(&mut self) -> io::Result<()> {
        match time::timeout(Duration::from_secs(30), self.run_once_impl()).await {
            Ok(o) => o,
            Err(..) => {
                error!("server-loader task timeout, url: {}", self.config_url);
                Err(io::ErrorKind::TimedOut.into())
            }
        }
    }

    async fn run_once_impl(&mut self) -> io::Result<()> {
        const SHADOWSOCKS_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

        let start_time = Instant::now();

        let req = match hyper::Request::builder()
            .header("User-Agent", SHADOWSOCKS_USER_AGENT)
            .header("Accept-Encoding", "deflate, gzip, br, zstd")
            .method("GET")
            .uri(&self.config_url)
            .body(String::new())
        {
            Ok(r) => r,
            Err(err) => {
                error!("server-loader task failed to make hyper::Request, error: {}", err);
                return Err(io::Error::other(err));
            }
        };

        let mut rsp = match self.http_client.send_request(self.context.clone(), req, None).await {
            Ok(r) => r,
            Err(err) => {
                error!("server-loader task failed to get {}, error: {}", self.config_url, err);
                return Err(io::Error::other(err));
            }
        };

        trace!("sever-loader task fetch response: {:?}", rsp);

        let fetch_time = Instant::now();

        // Check status=200
        if rsp.status() != StatusCode::OK {
            error!(
                "server-loader task failed to get {}, status: {}",
                self.config_url,
                rsp.status()
            );
            return Err(io::Error::other(format!("status: {}", rsp.status())));
        }

        // Content-Type: application/json; charset=utf-8
        // mandatory in standard SIP008
        match rsp.headers().get("Content-Type") {
            Some(h) => match h.to_str() {
                Ok(hstr) => match hstr.parse::<Mime>() {
                    Ok(content_type) => {
                        if content_type.type_() == mime::APPLICATION
                            && content_type.subtype() == mime::JSON
                            && content_type.get_param(mime::CHARSET) == Some(mime::UTF_8)
                        {
                            trace!("checked Content-Type: {:?}", h);
                        } else {
                            warn!(
                                "Content-Type is not \"application/json; charset=utf-8\", which is mandatory in standard SIP008. found {:?}",
                                h
                            );
                        }
                    }
                    Err(err) => {
                        warn!("Content-Type parse failed, value: {:?}, error: {}", h, err);
                    }
                },
                Err(..) => {
                    warn!("Content-Type is not a UTF-8 string: {:?}", h);
                }
            },
            None => {
                warn!("missing Content-Type in SIP008 response from {}", self.config_url);
            }
        }

        let content_encoding = match rsp.headers().get(http::header::CONTENT_ENCODING) {
            None => ContentEncoding::Identity,
            Some(ce) => match ContentEncoding::try_from(ce) {
                Ok(ce) => ce,
                Err(..) => {
                    error!("unrecognized Content-Encoding: {:?}", ce);
                    return Err(io::Error::other("unrecognized Content-Encoding"));
                }
            },
        };

        let body = read_body(content_encoding, &mut rsp).await?;
        let parsed_body = match String::from_utf8(body) {
            Ok(b) => b,
            Err(..) => return Err(io::Error::other("body contains non-utf8 bytes")),
        };

        let online_config = match Config::load_from_str(&parsed_body, ConfigType::OnlineConfig) {
            Ok(c) => c,
            Err(err) => {
                error!(
                    "server-loader task failed to load from url: {}, error: {}",
                    self.config_url, err
                );
                return Err(io::Error::other(err));
            }
        };

        if let Err(err) = online_config.check_integrity() {
            error!(
                "server-loader task failed to load from url: {}, error: {}",
                self.config_url, err
            );
            return Err(io::Error::other(err));
        }

        let after_read_time = Instant::now();

        // Check plugin whitelist
        if let Some(ref allowed_plugins) = self.allowed_plugins {
            for server in &online_config.server {
                if let Some(plugin) = server.config.plugin() {
                    if !allowed_plugins.contains(&plugin.plugin) {
                        error!(
                            "server-loader task found not allowed plugin: {}, url: {}",
                            plugin.plugin, self.config_url
                        );
                        return Err(io::Error::other(format!("not allowed plugin: {}", plugin.plugin)));
                    }
                }
            }
        }

        // Merge with static servers
        let server_len = online_config.server.len();

        // Update into ping balancers
        if let Err(err) = self
            .balancer
            .reset_servers(online_config.server, &[ServerSource::OnlineConfig])
            .await
        {
            error!(
                "server-loader task failed to reset balancer, url: {}, error: {}",
                self.config_url, err
            );
            return Err(err);
        };

        let finish_time = Instant::now();

        debug!(
            "server-loader task finished loading {} servers from url: {}, fetch time: {:?}, read time: {:?}, load time: {:?}, total time: {:?}",
            server_len,
            self.config_url,
            fetch_time - start_time,
            after_read_time - fetch_time,
            finish_time - after_read_time,
            finish_time - start_time,
        );

        Ok(())
    }

    /// Start service loop
    pub async fn run(mut self) -> io::Result<()> {
        debug!(
            "server-loader task started, url: {}, update interval: {:?}",
            self.config_url, self.config_update_interval
        );

        loop {
            time::sleep(self.config_update_interval).await;
            let _ = self.run_once().await;
        }
    }
}
