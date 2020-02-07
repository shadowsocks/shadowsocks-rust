//! Server network flow statistic

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

/// Flow statistic for one server
pub struct FlowStatistic {
    tx: AtomicU64,
    rx: AtomicU64,
}

impl FlowStatistic {
    /// Create an empty statistic
    pub fn new() -> FlowStatistic {
        FlowStatistic {
            tx: AtomicU64::new(0),
            rx: AtomicU64::new(0),
        }
    }

    /// Total bytes transferred
    pub fn tx(&self) -> u64 {
        self.tx.load(Ordering::Acquire)
    }

    /// Add bytes transferred
    pub fn incr_tx(&self, tx: u64) {
        self.tx.fetch_add(tx, Ordering::Release);
    }

    /// Total bytes received
    pub fn rx(&self) -> u64 {
        self.rx.load(Ordering::Acquire)
    }

    /// Add bytes received
    pub fn incr_rx(&self, rx: u64) {
        self.rx.fetch_add(rx, Ordering::Release);
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
}

impl Default for ServerFlowStatistic {
    fn default() -> ServerFlowStatistic {
        ServerFlowStatistic::new()
    }
}
