//! Identifier of server

use std::{
    fmt::{self, Debug},
    sync::atomic::{AtomicU64, Ordering},
};

use shadowsocks::ServerConfig;
use tokio::sync::Mutex;

use super::server_stat::{Score, ServerStat};

/// Server's statistic score
pub struct ServerScore {
    stat_data: Mutex<ServerStat>,
    score: AtomicU64,
}

impl ServerScore {
    /// Create a `ServerScore`
    pub fn new() -> ServerScore {
        ServerScore {
            stat_data: Mutex::new(ServerStat::new()),
            score: AtomicU64::new(0),
        }
    }

    /// Get server's current statistic scores
    pub fn score(&self) -> u64 {
        self.score.load(Ordering::Acquire)
    }

    /// Append a `Score` into statistic and recalculate score of the server
    pub async fn push_score(&self, score: Score) -> u64 {
        let updated_score = {
            let mut stat = self.stat_data.lock().await;
            stat.push_score(score)
        };
        self.score.store(updated_score, Ordering::Release);
        updated_score
    }

    /// Report request failure of this server, which will eventually records an `Errored` score
    pub async fn report_failure(&self) -> u64 {
        self.push_score(Score::Errored).await
    }
}

impl Debug for ServerScore {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ServerScore").field("score", &self.score()).finish()
    }
}

/// Identifier of a remote server
pub trait ServerIdent {
    /// Get server's score
    fn server_score<'a>(&'a self) -> &'a ServerScore;
    /// Get server's configuration
    fn server_config<'a>(&'a self) -> &'a ServerConfig;
}

/// Basic default identifer for a server
pub struct BasicServerIdent {
    score: ServerScore,
    svr_cfg: ServerConfig,
}

impl BasicServerIdent {
    /// Create a `BasicServerIdent`
    pub fn new(svr_cfg: ServerConfig) -> BasicServerIdent {
        BasicServerIdent {
            score: ServerScore::new(),
            svr_cfg,
        }
    }
}

impl ServerIdent for BasicServerIdent {
    fn server_config<'a>(&'a self) -> &'a ServerConfig {
        &self.svr_cfg
    }

    fn server_score<'a>(&'a self) -> &'a ServerScore {
        &self.score
    }
}
