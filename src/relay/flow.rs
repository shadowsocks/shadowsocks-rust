//! Server network flow statistic

use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use crate::config::Config;

/// Flow statistic for one server
pub struct FlowStatistic {
    tx: AtomicUsize,
    rx: AtomicUsize,
}

impl FlowStatistic {
    /// Create an empty statistic
    pub fn new() -> FlowStatistic {
        FlowStatistic {
            tx: AtomicUsize::new(0),
            rx: AtomicUsize::new(0),
        }
    }

    /// Total bytes transferred
    pub fn tx(&self) -> usize {
        self.tx.load(Ordering::Acquire)
    }

    /// Add bytes transferred
    pub fn incr_tx(&self, tx: usize) {
        self.tx.fetch_add(tx, Ordering::AcqRel);
    }

    /// Total bytes received
    pub fn rx(&self) -> usize {
        self.rx.load(Ordering::Acquire)
    }

    /// Add bytes received
    pub fn incr_rx(&self, rx: usize) {
        self.rx.fetch_add(rx, Ordering::AcqRel);
    }
}

impl Default for FlowStatistic {
    fn default() -> FlowStatistic {
        FlowStatistic::new()
    }
}

/// Shadowsocks Server flow statistic
pub struct ServerFlowStatistic {
    tcp: FlowStatistic,
    udp: FlowStatistic,
}

/// Shared reference for ServerFlowStatistic
pub type SharedServerFlowStatistic = Arc<ServerFlowStatistic>;

impl ServerFlowStatistic {
    /// Create a new ServerFlowStatistic
    pub fn new() -> ServerFlowStatistic {
        ServerFlowStatistic {
            tcp: FlowStatistic::new(),
            udp: FlowStatistic::new(),
        }
    }

    /// Create a new shared reference of ServerFlowStatistic
    pub fn new_shared() -> SharedServerFlowStatistic {
        Arc::new(ServerFlowStatistic::new())
    }

    /// TCP relay server flow statistic
    pub fn tcp(&self) -> &FlowStatistic {
        &self.tcp
    }

    /// UDP relay server flow statistic
    pub fn udp(&self) -> &FlowStatistic {
        &self.udp
    }

    /// Transmission statistic for manager
    pub fn trans_stat(&self) -> usize {
        self.tcp().tx() + self.tcp().rx() + self.udp().tx() + self.udp.rx()
    }
}

impl Default for ServerFlowStatistic {
    fn default() -> ServerFlowStatistic {
        ServerFlowStatistic::new()
    }
}

/// FlowStatic for multiple servers
pub struct MultiServerFlowStatistic {
    servers: BTreeMap<u16, SharedServerFlowStatistic>,
}

/// Shared reference for `MultiServerFlowStatistic`
pub type SharedMultiServerFlowStatistic = Arc<MultiServerFlowStatistic>;

impl MultiServerFlowStatistic {
    /// Create statistics for every servers in config
    pub fn new(config: &Config) -> MultiServerFlowStatistic {
        let mut servers = BTreeMap::new();
        for svr_cfg in &config.server {
            servers.insert(svr_cfg.addr().port(), ServerFlowStatistic::new_shared());
        }

        MultiServerFlowStatistic { servers }
    }

    /// Create a new shared reference for MultiServerFlowStatistic
    pub fn new_shared(config: &Config) -> SharedMultiServerFlowStatistic {
        Arc::new(MultiServerFlowStatistic::new(config))
    }

    /// Get ServerFlowStatistic by port
    pub fn get(&self, port: u16) -> Option<&SharedServerFlowStatistic> {
        self.servers.get(&port)
    }
}
