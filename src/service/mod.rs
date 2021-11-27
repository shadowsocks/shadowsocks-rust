//! Service launchers

#[cfg(feature = "local")]
pub mod local;
#[cfg(feature = "manager")]
pub mod manager;
#[cfg(feature = "server")]
pub mod server;
