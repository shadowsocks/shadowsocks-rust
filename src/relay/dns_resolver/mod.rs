#[cfg(feature = "trust-dns")]
mod trust_dns_resolver;

#[cfg(not(feature = "trust-dns"))]
mod tokio_dns_resolver;

#[cfg(feature = "trust-dns")]
pub use self::trust_dns_resolver::resolve;

#[cfg(feature = "trust-dns")]
pub use self::trust_dns_resolver::create_resolver;

#[cfg(not(feature = "trust-dns"))]
pub use self::tokio_dns_resolver::resolve;
