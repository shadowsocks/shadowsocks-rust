//! Asynchronous wrapper of tun interface

use std::{
    io,
    ops::{Deref, DerefMut},
    os::unix::io::{AsRawFd, RawFd},
};

use smoltcp::{
    phy::{Device, DeviceCapabilities, Medium, RxToken, TunTapInterface, TxToken},
    time::Instant,
};
use tokio::io::unix::AsyncFd;

struct SendableTunTapInterface(TunTapInterface);

/// TunTapInterface is not Sendable because it contains a Rc field.
/// The Rc field will be shared between all TxToken.
///
/// But in this wrapper, we won't expose the RxToken and TxToken, so it is safe to Send between threads.
unsafe impl Send for SendableTunTapInterface {}

impl AsRawFd for SendableTunTapInterface {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl Deref for SendableTunTapInterface {
    type Target = TunTapInterface;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SendableTunTapInterface {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub struct TunInterface {
    iface: AsyncFd<SendableTunTapInterface>,
}

impl TunInterface {
    pub fn new(name: &str) -> io::Result<TunInterface> {
        let iface = SendableTunTapInterface(TunTapInterface::new(name, Medium::Ip)?);
        Ok(TunInterface {
            iface: AsyncFd::new(iface)?,
        })
    }

    pub async fn receive<R, F>(&mut self, timestamp: Instant, consume: F) -> io::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        loop {
            let mut ready = self.iface.readable_mut().await?;
            let result = ready.try_io(|iface| match iface.get_mut().receive() {
                Some(token) => return Ok(token),
                None => Err(io::ErrorKind::WouldBlock.into()),
            });

            match result {
                Ok(Ok((token, _))) => {
                    return token
                        .consume(timestamp, consume)
                        .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
                }
                Ok(Err(err)) => return Err(err),
                Err(..) => continue,
            }
        }
    }

    pub async fn transmit(&mut self, timestamp: Instant, buffer: &[u8]) -> io::Result<()> {
        loop {
            let mut ready = self.iface.writable_mut().await?;

            let result = ready.try_io(|iface| match iface.get_mut().transmit() {
                Some(token) => Ok(token),
                None => Err(io::ErrorKind::WouldBlock.into()),
            });

            match result {
                Ok(Ok(token)) => {
                    return token
                        .consume(timestamp, buffer.len(), |xbuf| {
                            xbuf.copy_from_slice(buffer);
                            Ok(())
                        })
                        .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
                }
                Ok(Err(err)) => return Err(err),
                Err(..) => continue,
            }
        }
    }

    pub fn capabilities(&self) -> DeviceCapabilities {
        self.iface.get_ref().capabilities()
    }
}
