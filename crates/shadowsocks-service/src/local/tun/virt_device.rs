//! Virtual Device for receiving packets from tun

use std::{
    marker::PhantomData,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use smoltcp::{
    phy::{self, Device, DeviceCapabilities},
    time::Instant,
};
use tokio::sync::mpsc;

pub struct VirtTunDevice {
    capabilities: DeviceCapabilities,
    in_buf: mpsc::UnboundedReceiver<Vec<u8>>,
    out_buf: mpsc::UnboundedSender<Vec<u8>>,
    in_buf_avail: Arc<AtomicBool>,
}

impl VirtTunDevice {
    #[allow(clippy::type_complexity)]
    pub fn new(
        capabilities: DeviceCapabilities,
    ) -> (
        Self,
        mpsc::UnboundedReceiver<Vec<u8>>,
        mpsc::UnboundedSender<Vec<u8>>,
        Arc<AtomicBool>,
    ) {
        let (iface_tx, iface_output) = mpsc::unbounded_channel();
        let (iface_input, iface_rx) = mpsc::unbounded_channel();
        let in_buf_avail = Arc::new(AtomicBool::new(false));

        (
            Self {
                capabilities,
                in_buf: iface_rx,
                out_buf: iface_tx,
                in_buf_avail: in_buf_avail.clone(),
            },
            iface_output,
            iface_input,
            in_buf_avail,
        )
    }

    #[inline]
    pub fn recv_available(&self) -> bool {
        self.in_buf_avail.load(Ordering::Acquire)
    }
}

impl Device for VirtTunDevice {
    type RxToken<'a> = VirtRxToken<'a>;
    type TxToken<'a> = VirtTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let Ok(buffer) = self.in_buf.try_recv() {
            let rx = Self::RxToken {
                buffer,
                phantom_device: PhantomData,
            };
            let tx = VirtTxToken(self);
            return Some((rx, tx));
        }
        self.in_buf_avail.store(false, Ordering::Release);
        None
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(VirtTxToken(self))
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
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

pub struct VirtTxToken<'a>(&'a mut VirtTunDevice);

impl phy::TxToken for VirtTxToken<'_> {
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
