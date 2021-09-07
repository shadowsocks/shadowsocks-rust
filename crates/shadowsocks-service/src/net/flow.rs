//! Server flow statistic

use std::sync::atomic::Ordering;

#[cfg(not(any(target_arch = "mips", target_arch = "powerpc")))]
type FlowCounter = std::sync::atomic::AtomicU64;
#[cfg(any(target_arch = "mips", target_arch = "powerpc"))]
type FlowCounter = std::sync::atomic::AtomicU32;

/// Connection flow statistic
pub struct FlowStat {
    tx: FlowCounter,
    rx: FlowCounter,
}

impl Default for FlowStat {
    fn default() -> Self {
        FlowStat {
            tx: FlowCounter::new(0),
            rx: FlowCounter::new(0),
        }
    }
}

impl FlowStat {
    /// Create an empty flow statistic
    pub fn new() -> FlowStat {
        FlowStat::default()
    }

    /// Transmitted bytes count
    pub fn tx(&self) -> u64 {
        self.tx.load(Ordering::Relaxed) as _
    }

    /// Increase transmitted bytes
    pub fn incr_tx(&self, n: u64) {
        self.tx.fetch_add(n as _, Ordering::AcqRel);
    }

    /// Received bytes count
    pub fn rx(&self) -> u64 {
        self.rx.load(Ordering::Relaxed) as _
    }

    /// Increase received bytes
    pub fn incr_rx(&self, n: u64) {
        self.rx.fetch_add(n as _, Ordering::AcqRel);
    }
}
