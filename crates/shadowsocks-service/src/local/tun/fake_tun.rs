//! Fake `tun` for those platforms that doesn't support `tun`

use std::{
    io::{self, Read, Write},
    net::Ipv4Addr,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tun::{Configuration, Device, Error as TunError};

pub struct FakeQueue;

impl Read for FakeQueue {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::Other, "not implemented"))
    }
}

impl Write for FakeQueue {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::Other, "not implemented"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Other, "not implemented"))
    }
}

pub struct FakeDevice;

impl Device for FakeDevice {
    type Queue = FakeQueue;

    fn name(&self) -> tun::Result<String> {
        Err(TunError::NotImplemented)
    }

    fn set_name(&mut self, _: &str) -> tun::Result<()> {
        Err(TunError::NotImplemented)
    }

    fn enabled(&mut self, _: bool) -> tun::Result<()> {
        Err(TunError::NotImplemented)
    }

    fn address(&self) -> tun::Result<Ipv4Addr> {
        Err(TunError::NotImplemented)
    }

    fn set_address(&mut self, _: Ipv4Addr) -> tun::Result<()> {
        Err(TunError::NotImplemented)
    }

    fn destination(&self) -> tun::Result<Ipv4Addr> {
        Err(TunError::NotImplemented)
    }

    fn set_destination(&mut self, _: Ipv4Addr) -> tun::Result<()> {
        Err(TunError::NotImplemented)
    }

    fn broadcast(&self) -> tun::Result<Ipv4Addr> {
        Err(TunError::NotImplemented)
    }

    fn set_broadcast(&mut self, _: Ipv4Addr) -> tun::Result<()> {
        Err(TunError::NotImplemented)
    }

    fn netmask(&self) -> tun::Result<Ipv4Addr> {
        Err(TunError::NotImplemented)
    }

    fn set_netmask(&mut self, _: Ipv4Addr) -> tun::Result<()> {
        Err(TunError::NotImplemented)
    }

    fn mtu(&self) -> tun::Result<i32> {
        Err(TunError::NotImplemented)
    }

    fn set_mtu(&mut self, _: i32) -> tun::Result<()> {
        Err(TunError::NotImplemented)
    }

    fn queue(&mut self, _: usize) -> Option<&mut Self::Queue> {
        None
    }
}

impl Read for FakeDevice {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::Other, "not implemented"))
    }
}

impl Write for FakeDevice {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::Other, "not implemented"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Other, "not implemented"))
    }
}

pub struct AsyncDevice(FakeDevice);

impl AsyncDevice {
    pub fn get_ref(&self) -> &FakeDevice {
        &self.0
    }

    pub fn get_mut(&mut self) -> &mut FakeDevice {
        &mut self.0
    }
}

impl AsyncRead for AsyncDevice {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Err(io::Error::new(io::ErrorKind::Other, "not implemented")).into()
    }
}

impl AsyncWrite for AsyncDevice {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &[u8]) -> Poll<io::Result<usize>> {
        Err(io::Error::new(io::ErrorKind::Other, "not implemented")).into()
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Err(io::Error::new(io::ErrorKind::Other, "not implemented")).into()
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Err(io::Error::new(io::ErrorKind::Other, "not implemented")).into()
    }
}

/// Create a TUN device with the given name.
pub fn create_as_async(_: &Configuration) -> Result<AsyncDevice, TunError> {
    Err(TunError::NotImplemented)
}
