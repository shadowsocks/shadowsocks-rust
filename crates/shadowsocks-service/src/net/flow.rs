//! Server flow statistic

use std::sync::atomic::{AtomicU64, Ordering};

pub struct FlowStat {
    tx: AtomicU64,
    rx: AtomicU64,
}

impl FlowStat {
    pub fn new() -> FlowStat {
        FlowStat {
            tx: AtomicU64::new(0),
            rx: AtomicU64::new(0),
        }
    }

    pub fn tx(&self) -> u64 {
        self.tx.load(Ordering::Relaxed)
    }

    pub fn incr_tx(&self, n: u64) {
        self.tx.fetch_add(n, Ordering::AcqRel);
    }

    pub fn rx(&self) -> u64 {
        self.rx.load(Ordering::Relaxed)
    }

    pub fn incr_rx(&self, n: u64) {
        self.rx.fetch_add(n, Ordering::AcqRel);
    }
}
