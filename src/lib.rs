#![crate_type="lib"]
#![crate_name="shadowsocks"]
#![feature(phase, unsafe_destructor)]

extern crate serialize;
#[phase(plugin, link)]
extern crate log;

pub const VERSION: &'static str = "0.0.1";

pub mod config;
pub mod relay;
pub mod tcprelay;
pub mod udprelay;
mod crypto;
