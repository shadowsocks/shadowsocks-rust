//! Identifier of server

use std::{
    fmt::{self, Debug},
    sync::atomic::{AtomicU64, Ordering},
};

use shadowsocks::ServerConfig;
use tokio::sync::Mutex;

use super::server_stat::{Score, ServerStat};

/// Server's identifier
pub struct ServerScore {
    stat_data: Mutex<ServerStat>,
    score: AtomicU64,
}

impl ServerScore {
    pub fn new() -> ServerScore {
        ServerScore {
            stat_data: Mutex::new(ServerStat::new()),
            score: AtomicU64::new(0),
        }
    }

    pub fn score(&self) -> u64 {
        self.score.load(Ordering::Acquire)
    }

    pub async fn push_score(&self, score: Score) -> u64 {
        let updated_score = {
            let mut stat = self.stat_data.lock().await;
            stat.push_score(score)
        };
        self.score.store(updated_score, Ordering::Release);
        updated_score
    }

    pub async fn report_failure(&self) -> u64 {
        self.push_score(Score::Errored).await
    }
}

impl Debug for ServerScore {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ServerScore").field("score", &self.score()).finish()
    }
}

pub trait ServerIdent {
    fn server_score<'a>(&'a self) -> &'a ServerScore;
    fn server_config<'a>(&'a self) -> &'a ServerConfig;
}

pub struct BasicServerIdent {
    score: ServerScore,
    svr_cfg: ServerConfig,
}

impl BasicServerIdent {
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
