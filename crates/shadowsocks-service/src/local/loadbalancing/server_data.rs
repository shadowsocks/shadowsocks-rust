//! Identifier of server

use std::{
    fmt::{self, Debug},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use shadowsocks::ServerConfig;
use tokio::sync::Mutex;

use super::server_stat::{Score, ServerStat};

pub struct ServerIdent<E = ()> {
    svr_cfg: ServerConfig,
    extra: E,
    stat_data: Mutex<ServerStat>,
    score: AtomicU64,
}

impl<E> ServerIdent<E> {
    pub fn new(svr_cfg: ServerConfig, extra: E) -> ServerIdent<E> {
        ServerIdent {
            svr_cfg,
            extra,
            stat_data: Mutex::new(ServerStat::new()),
            score: AtomicU64::new(0),
        }
    }

    pub fn extra(&self) -> &E {
        &self.extra
    }

    pub fn extra_mut(&mut self) -> &mut E {
        &mut self.extra
    }

    pub fn server_config(&self) -> &ServerConfig {
        &self.svr_cfg
    }

    pub fn server_config_mut(&mut self) -> &mut ServerConfig {
        &mut self.svr_cfg
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

impl<E> Debug for ServerIdent<E>
where
    E: Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ServerIdent")
            .field("svr_cfg", &self.svr_cfg)
            .field("score", &self.score())
            .field("extra", &self.extra)
            .finish()
    }
}

pub type SharedServerIdent<E> = Arc<ServerIdent<E>>;
