//! Fake `tun` for those platforms that doesn't support `tun`

#![allow(dead_code)]

use std::{
    io::{self, Read, Write},
    net::IpAddr,
    ops::{Deref, DerefMut},
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// TUN interface OSI layer of operation.
#[derive(Clone, Copy, Default, Debug, Eq, PartialEq)]
pub enum Layer {
    L2,
    #[default]
    L3,
}

/// Configuration builder for a TUN interface.
#[derive(Clone, Default, Debug)]
pub struct Configuration;

impl Configuration {
    /// Set the tun name.
    ///
    /// [Note: on macOS, the tun name must be the form `utunx` where `x` is a number, such as `utun3`. -- end note]
    pub fn tun_name<S: AsRef<str>>(&mut self, _tun_name: S) -> &mut Self {
        self
    }

    /// Set the address.
    pub fn address(&mut self, _value: IpAddr) -> &mut Self {
        self
    }

    /// Set the destination address.
    pub fn destination(&mut self, _value: IpAddr) -> &mut Self {
        self
    }

    /// Set the broadcast address.
    pub fn broadcast(&mut self, _value: IpAddr) -> &mut Self {
        self
    }

    /// Set the netmask.
    pub fn netmask(&mut self, _value: IpAddr) -> &mut Self {
        self
    }

    /// Set the MTU.
    pub fn mtu(&mut self, _value: u16) -> &mut Self {
        self
    }

    /// Set the interface to be enabled once created.
    pub fn up(&mut self) -> &mut Self {
        self
    }

    /// Set the interface to be disabled once created.
    pub fn down(&mut self) -> &mut Self {
        self
    }

    /// Set the OSI layer of operation.
    pub fn layer(&mut self, _value: Layer) -> &mut Self {
        self
    }

    /// Set the raw fd.
    #[cfg(unix)]
    pub fn raw_fd(&mut self, _fd: ::std::os::fd::RawFd) -> &mut Self {
        self
    }
}

/// tun Error type
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("not implemented")]
    NotImplemented,

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T, E = Error> = ::std::result::Result<T, E>;

/// A TUN abstract device interface.
pub trait AbstractDevice: Read + Write {
    /// Reconfigure the device.
    fn configure(&mut self, _config: &Configuration) -> Result<()> {
        Ok(())
    }

    /// Get the device index.
    fn tun_index(&self) -> Result<i32>;

    /// Get the device tun name.
    fn tun_name(&self) -> Result<String>;

    /// Set the device tun name.
    fn set_tun_name(&mut self, tun_name: &str) -> Result<()>;

    /// Turn on or off the interface.
    fn enabled(&mut self, value: bool) -> Result<()>;

    /// Get the address.
    fn address(&self) -> Result<IpAddr>;

    /// Set the address.
    fn set_address(&mut self, value: IpAddr) -> Result<()>;

    /// Get the destination address.
    fn destination(&self) -> Result<IpAddr>;

    /// Set the destination address.
    fn set_destination(&mut self, value: IpAddr) -> Result<()>;

    /// Get the broadcast address.
    fn broadcast(&self) -> Result<IpAddr>;

    /// Set the broadcast address.
    fn set_broadcast(&mut self, value: IpAddr) -> Result<()>;

    /// Get the netmask.
    fn netmask(&self) -> Result<IpAddr>;

    /// Set the netmask.
    fn set_netmask(&mut self, value: IpAddr) -> Result<()>;

    /// Get the MTU.
    fn mtu(&self) -> Result<u16>;

    /// Set the MTU.
    ///
    /// [Note: This setting has no effect on the Windows platform due to the mtu of wintun is always 65535. --end note]
    fn set_mtu(&mut self, value: u16) -> Result<()>;

    /// Return whether the underlying tun device on the platform has packet information
    ///
    /// [Note: This value is not used to specify whether the packets delivered from/to tun have packet information. -- end note]
    fn packet_information(&self) -> bool;
}

pub struct FakeQueue;

impl Read for FakeQueue {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("not implemented"))
    }
}

impl Write for FakeQueue {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("not implemented"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("not implemented"))
    }
}

pub struct FakeDevice;

impl AbstractDevice for FakeDevice {
    fn tun_name(&self) -> Result<String> {
        Err(Error::NotImplemented)
    }

    fn tun_index(&self) -> Result<i32> {
        Err(Error::NotImplemented)
    }

    fn set_tun_name(&mut self, _: &str) -> Result<()> {
        Err(Error::NotImplemented)
    }

    fn enabled(&mut self, _: bool) -> Result<()> {
        Err(Error::NotImplemented)
    }

    fn address(&self) -> Result<IpAddr> {
        Err(Error::NotImplemented)
    }

    fn set_address(&mut self, _: IpAddr) -> Result<()> {
        Err(Error::NotImplemented)
    }

    fn destination(&self) -> Result<IpAddr> {
        Err(Error::NotImplemented)
    }

    fn set_destination(&mut self, _: IpAddr) -> Result<()> {
        Err(Error::NotImplemented)
    }

    fn broadcast(&self) -> Result<IpAddr> {
        Err(Error::NotImplemented)
    }

    fn set_broadcast(&mut self, _: IpAddr) -> Result<()> {
        Err(Error::NotImplemented)
    }

    fn netmask(&self) -> Result<IpAddr> {
        Err(Error::NotImplemented)
    }

    fn set_netmask(&mut self, _: IpAddr) -> Result<()> {
        Err(Error::NotImplemented)
    }

    fn mtu(&self) -> Result<u16> {
        Err(Error::NotImplemented)
    }

    fn set_mtu(&mut self, _: u16) -> Result<()> {
        Err(Error::NotImplemented)
    }

    fn packet_information(&self) -> bool {
        false
    }
}

impl Read for FakeDevice {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("not implemented"))
    }
}

impl Write for FakeDevice {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("not implemented"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("not implemented"))
    }
}

pub struct AsyncDevice(FakeDevice);

impl AsRef<FakeDevice> for AsyncDevice {
    fn as_ref(&self) -> &FakeDevice {
        &self.0
    }
}

impl AsMut<FakeDevice> for AsyncDevice {
    fn as_mut(&mut self) -> &mut FakeDevice {
        &mut self.0
    }
}

impl Deref for AsyncDevice {
    type Target = FakeDevice;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for AsyncDevice {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsyncRead for AsyncDevice {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Err(io::Error::other("not implemented")).into()
    }
}

impl AsyncWrite for AsyncDevice {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &[u8]) -> Poll<io::Result<usize>> {
        Err(io::Error::other("not implemented")).into()
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Err(io::Error::other("not implemented")).into()
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Err(io::Error::other("not implemented")).into()
    }
}

/// Create a TUN device with the given name.
pub fn create_as_async(_: &Configuration) -> Result<AsyncDevice, Error> {
    Err(Error::NotImplemented)
}
