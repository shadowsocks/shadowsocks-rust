//! Identifier of server

use std::{
    fmt::{self, Debug},
    net::SocketAddr,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};

use shadowsocks::{net::ConnectOpts, ServerConfig};
use tokio::sync::Mutex;

use crate::{config::ServerInstanceConfig, local::context::ServiceContext};

use super::server_stat::{Score, ServerStat, ServerStatData};

/// Server's statistic score
pub struct ServerScore {
    stat_data: Mutex<ServerStat>,
    score: AtomicU32,
}

impl ServerScore {
    /// Create a `ServerScore`
    pub fn new(user_weight: f32, max_server_rtt: Duration, check_window: Duration) -> ServerScore {
        let max_server_rtt = max_server_rtt.as_millis() as u32;
        assert!(max_server_rtt > 0);

        ServerScore {
            stat_data: Mutex::new(ServerStat::new(user_weight, max_server_rtt, check_window)),
            score: AtomicU32::new(u32::MAX),
        }
    }

    /// Get server's current statistic scores
    pub fn score(&self) -> u32 {
        self.score.load(Ordering::Acquire)
    }

    /// Append a `Score` into statistic and recalculate score of the server
    pub async fn push_score(&self, score: Score) -> u32 {
        let updated_score = {
            let mut stat = self.stat_data.lock().await;
            stat.push_score(score)
        };
        self.score.store(updated_score, Ordering::Release);
        updated_score
    }

    /// Append a `Score` into statistic and recalculate score of the server
    pub async fn push_score_fetch_statistic(&self, score: Score) -> (u32, ServerStatData) {
        let (updated_score, data) = {
            let mut stat = self.stat_data.lock().await;
            (stat.push_score(score), *stat.data())
        };
        self.score.store(updated_score, Ordering::Release);
        (updated_score, data)
    }

    /// Report request failure of this server, which will eventually records an `Errored` score
    pub async fn report_failure(&self) -> u32 {
        self.push_score(Score::Errored).await
    }

    /// Get statistic data
    pub async fn stat_data(&self) -> ServerStatData {
        *self.stat_data.lock().await.data()
    }
}

impl Debug for ServerScore {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ServerScore").field("score", &self.score()).finish()
    }
}

/// Identifer for a server
#[derive(Debug)]
pub struct ServerIdent {
    tcp_score: ServerScore,
    udp_score: ServerScore,
    svr_cfg: ServerInstanceConfig,
    connect_opts: ConnectOpts,
}

impl ServerIdent {
    /// Create a `ServerIdent`
    pub fn new(
        context: Arc<ServiceContext>,
        svr_cfg: ServerInstanceConfig,
        max_server_rtt: Duration,
        check_window: Duration,
    ) -> ServerIdent {
        let mut connect_opts = context.connect_opts_ref().clone();

        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(fwmark) = svr_cfg.outbound_fwmark {
            connect_opts.fwmark = Some(fwmark);
        }

        if let Some(bind_local_addr) = svr_cfg.outbound_bind_addr {
            connect_opts.bind_local_addr = Some(SocketAddr::new(bind_local_addr, 0));
        }

        if let Some(ref bind_interface) = svr_cfg.outbound_bind_interface {
            connect_opts.bind_interface = Some(bind_interface.clone());
        }

        ServerIdent {
            tcp_score: ServerScore::new(svr_cfg.config.weight().tcp_weight(), max_server_rtt, check_window),
            udp_score: ServerScore::new(svr_cfg.config.weight().udp_weight(), max_server_rtt, check_window),
            svr_cfg,
            connect_opts,
        }
    }

    pub fn connect_opts_ref(&self) -> &ConnectOpts {
        &self.connect_opts
    }

    pub fn server_config(&self) -> &ServerConfig {
        &self.svr_cfg.config
    }

    pub fn server_config_mut(&mut self) -> &mut ServerConfig {
        &mut self.svr_cfg.config
    }

    pub fn server_instance_config(&self) -> &ServerInstanceConfig {
        &self.svr_cfg
    }

    pub fn tcp_score(&self) -> &ServerScore {
        &self.tcp_score
    }

    pub fn udp_score(&self) -> &ServerScore {
        &self.udp_score
    }
}
