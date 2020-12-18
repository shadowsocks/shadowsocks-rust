//! Server flow statistic

use std::sync::atomic::{AtomicU64, Ordering};

/// Connection flow statistic
pub struct FlowStat {
    tx: AtomicU64,
    rx: AtomicU64,
}

impl FlowStat {
    /// Create an empty flow statistic
    pub fn new() -> FlowStat {
        FlowStat {
            tx: AtomicU64::new(0),
            rx: AtomicU64::new(0),
        }
    }

    /// Transmitted bytes count
    pub fn tx(&self) -> u64 {
        self.tx.load(Ordering::Relaxed)
    }

    /// Increase transmitted bytes
    pub fn incr_tx(&self, n: u64) {
        self.tx.fetch_add(n, Ordering::AcqRel);
    }

    /// Received bytes count
    pub fn rx(&self) -> u64 {
        self.rx.load(Ordering::Relaxed)
    }

    /// Increase received bytes
    pub fn incr_rx(&self, n: u64) {
        self.rx.fetch_add(n, Ordering::AcqRel);
    }
}
