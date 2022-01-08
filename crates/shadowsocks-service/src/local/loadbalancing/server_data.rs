//! Identifier of server

use std::{
    fmt::{self, Debug},
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

use shadowsocks::ServerConfig;
use tokio::sync::Mutex;

use super::server_stat::{Score, ServerStat};

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

    /// Report request failure of this server, which will eventually records an `Errored` score
    pub async fn report_failure(&self) -> u32 {
        self.push_score(Score::Errored).await
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
    svr_cfg: ServerConfig,
}

impl ServerIdent {
    /// Create a `ServerIdent`
    pub fn new(svr_cfg: ServerConfig, max_server_rtt: Duration, check_window: Duration) -> ServerIdent {
        ServerIdent {
            tcp_score: ServerScore::new(svr_cfg.weight().tcp_weight(), max_server_rtt, check_window),
            udp_score: ServerScore::new(svr_cfg.weight().udp_weight(), max_server_rtt, check_window),
            svr_cfg,
        }
    }

    pub fn server_config(&self) -> &ServerConfig {
        &self.svr_cfg
    }

    pub fn server_config_mut(&mut self) -> &mut ServerConfig {
        &mut self.svr_cfg
    }

    pub fn tcp_score(&self) -> &ServerScore {
        &self.tcp_score
    }

    pub fn udp_score(&self) -> &ServerScore {
        &self.udp_score
    }
}
