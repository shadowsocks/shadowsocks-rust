//! Virtual Device for receiving packets from tun

use std::collections::VecDeque;

use smoltcp::{
    phy::{self, Device, DeviceCapabilities},
    time::Instant,
};
use tokio::sync::mpsc;

pub struct VirtTunDevice {
    capabilities: DeviceCapabilities,
    in_buf: VecDeque<Vec<u8>>,
    out_buf: mpsc::UnboundedSender<Vec<u8>>,
}

impl VirtTunDevice {
    pub fn new(capabilities: DeviceCapabilities, iface_tx: mpsc::UnboundedSender<Vec<u8>>) -> Self {
        Self {
            capabilities,
            in_buf: VecDeque::new(),
            out_buf: iface_tx,
        }
    }

    pub fn inject_packet(&mut self, buffer: Vec<u8>) {
        self.in_buf.push_back(buffer);
    }
}

impl<'a> Device<'a> for VirtTunDevice {
    type RxToken = VirtRxToken;
    type TxToken = VirtTxToken<'a>;

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        if let Some(buffer) = self.in_buf.pop_front() {
            let rx = Self::RxToken { buffer };
            let tx = VirtTxToken(self);
            return Some((rx, tx));
        }
        None
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        return Some(VirtTxToken(self));
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities.clone()
    }
}

pub struct VirtRxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for VirtRxToken {
    fn consume<R, F>(mut self, _timestamp: Instant, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        f(&mut self.buffer[..])
    }
}

pub struct VirtTxToken<'a>(&'a mut VirtTunDevice);

impl<'a> phy::TxToken for VirtTxToken<'a> {
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        self.0.out_buf.send(buffer).expect("channel closed unexpectly");
        result
    }
}
