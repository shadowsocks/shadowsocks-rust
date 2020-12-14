//! Trait of auto-proxy I/O

pub trait AutoProxyIo {
    fn is_proxied(&self) -> bool;

    fn is_bypassed(&self) -> bool {
        !self.is_proxied()
    }
}
