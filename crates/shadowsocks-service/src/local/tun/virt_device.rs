//! Virtual Device for receiving packets from tun

use std::marker::PhantomData;

use smoltcp::{
    phy::{self, Device, DeviceCapabilities},
    time::Instant,
};
use tokio::sync::mpsc;

pub struct VirtTunDevice {
    capabilities: DeviceCapabilities,
    in_buf: mpsc::UnboundedReceiver<Vec<u8>>,
    out_buf: mpsc::UnboundedSender<Vec<u8>>,
}

impl VirtTunDevice {
    pub fn new(
        capabilities: DeviceCapabilities,
    ) -> (Self, mpsc::UnboundedReceiver<Vec<u8>>, mpsc::UnboundedSender<Vec<u8>>) {
        let (iface_tx, iface_output) = mpsc::unbounded_channel();
        let (iface_input, iface_rx) = mpsc::unbounded_channel();

        (
            Self {
                capabilities,
                in_buf: iface_rx,
                out_buf: iface_tx,
            },
            iface_output,
            iface_input,
        )
    }
}

impl Device for VirtTunDevice {
    type RxToken<'a> = VirtRxToken<'a>;
    type TxToken<'a> = VirtTxToken<'a>;

    fn receive<'a>(&'a mut self, _timestamp: Instant) -> Option<(Self::RxToken<'a>, Self::TxToken<'a>)> {
        if let Ok(buffer) = self.in_buf.try_recv() {
            let rx = Self::RxToken {
                buffer,
                phantom_device: PhantomData::default(),
            };
            let tx = VirtTxToken(self);
            return Some((rx, tx));
        }
        None
    }

    fn transmit<'a>(&'a mut self, _timestamp: Instant) -> Option<Self::TxToken<'a>> {
        return Some(VirtTxToken(self));
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities.clone()
    }
}

pub struct VirtRxToken<'a> {
    buffer: Vec<u8>,
    phantom_device: PhantomData<&'a VirtTunDevice>,
}

impl phy::RxToken for VirtRxToken<'_> {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.buffer[..])
    }
}

pub struct VirtTxToken<'a>(&'a mut VirtTunDevice);

impl<'a> phy::TxToken for VirtTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        self.0.out_buf.send(buffer).expect("channel closed unexpectly");
        result
    }
}
