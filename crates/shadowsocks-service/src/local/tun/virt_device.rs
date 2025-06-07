//! Virtual Device for receiving packets from tun

use std::{
    marker::PhantomData,
    mem,
    ops::{Deref, DerefMut},
    sync::{
        Arc, LazyLock, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use bytes::BytesMut;
use smoltcp::{
    phy::{self, Device, DeviceCapabilities},
    time::Instant,
};
use tokio::sync::mpsc;

pub struct VirtTunDevice {
    capabilities: DeviceCapabilities,
    in_buf: mpsc::UnboundedReceiver<TokenBuffer>,
    out_buf: mpsc::UnboundedSender<TokenBuffer>,
    in_buf_avail: Arc<AtomicBool>,
}

impl VirtTunDevice {
    #[allow(clippy::type_complexity)]
    pub fn new(
        capabilities: DeviceCapabilities,
    ) -> (
        Self,
        mpsc::UnboundedReceiver<TokenBuffer>,
        mpsc::UnboundedSender<TokenBuffer>,
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
    buffer: TokenBuffer,
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
        let mut buffer = TokenBuffer::with_capacity(len);
        unsafe {
            buffer.set_len(len);
        }

        let result = f(&mut buffer);
        self.0.out_buf.send(buffer).expect("channel closed unexpectedly");
        result
    }
}

// Maximum number of TokenBuffer cached globally.
//
// Each of them has capacity 65536 (defined in tun/mod.rs), so 64 * 65536 = 4MB.
const TOKEN_BUFFER_LIST_MAX_SIZE: usize = 64;
static TOKEN_BUFFER_LIST: LazyLock<Mutex<Vec<BytesMut>>> = LazyLock::new(|| Mutex::new(Vec::new()));

pub struct TokenBuffer {
    buffer: BytesMut,
}

impl Drop for TokenBuffer {
    fn drop(&mut self) {
        let mut list = TOKEN_BUFFER_LIST.lock().unwrap();
        if list.len() >= TOKEN_BUFFER_LIST_MAX_SIZE {
            return;
        }

        let empty_buffer = BytesMut::new();
        let mut buffer = mem::replace(&mut self.buffer, empty_buffer);
        buffer.clear();

        list.push(buffer);
    }
}

impl TokenBuffer {
    pub fn with_capacity(cap: usize) -> Self {
        let mut list = TOKEN_BUFFER_LIST.lock().unwrap();
        if let Some(mut buffer) = list.pop() {
            buffer.reserve(cap);
            return Self { buffer };
        }
        Self {
            buffer: BytesMut::with_capacity(cap),
        }
    }
}

impl Deref for TokenBuffer {
    type Target = BytesMut;

    fn deref(&self) -> &Self::Target {
        &self.buffer
    }
}

impl DerefMut for TokenBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buffer
    }
}
