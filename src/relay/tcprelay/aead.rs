//! AEAD packet I/O facilities
//!
//! AEAD protocol is defined in https://shadowsocks.org/en/spec/AEAD.html.
//!
//! ```plain
//! TCP request (before encryption)
//! +------+---------------------+------------------+
//! | ATYP | Destination Address | Destination Port |
//! +------+---------------------+------------------+
//! |  1   |       Variable      |         2        |
//! +------+---------------------+------------------+
//!
//! TCP request (after encryption, *ciphertext*)
//! +--------+--------------+------------------+--------------+---------------+
//! | NONCE  |  *HeaderLen* |   HeaderLen_TAG  |   *Header*   |  Header_TAG   |
//! +--------+--------------+------------------+--------------+---------------+
//! | Fixed  |       2      |       Fixed      |   Variable   |     Fixed     |
//! +--------+--------------+------------------+--------------+---------------+
//!
//! TCP Chunk (before encryption)
//! +----------+
//! |  DATA    |
//! +----------+
//! | Variable |
//! +----------+
//!
//! TCP Chunk (after encryption, *ciphertext*)
//! +--------------+---------------+--------------+------------+
//! |  *DataLen*   |  DataLen_TAG  |    *Data*    |  Data_TAG  |
//! +--------------+---------------+--------------+------------+
//! |      2       |     Fixed     |   Variable   |   Fixed    |
//! +--------------+---------------+--------------+------------+
//! ```
use futures::ready;
use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use shadowsocks_crypto::v1::{CipherKind, Cipher};


use std::{
    cmp,
    io,
    marker::Unpin,
    pin::Pin,
    slice,
    task::{Context, Poll},
    u16,
};


/// AEAD packet payload must be smaller than 0x3FFF
const MAX_PACKET_SIZE: usize = 0x3FFF;

#[derive(Debug)]
enum DecryptReadStep {
    Length,
    Data(usize),
}

/// Reader wrapper that will decrypt data automatically
pub struct DecryptedReader {
    buffer: BytesMut,
    data: BytesMut,
    cipher: Cipher,
    pos: usize,
    tag_size: usize,
    steps: DecryptReadStep,
    got_final: bool,
}

impl DecryptedReader {
    pub fn new(method: CipherKind, key: &[u8], nonce: &[u8]) -> DecryptedReader {
        DecryptedReader {
            // Initialize for the first length block
            buffer: BytesMut::with_capacity(2 + method.tag_len()),
            data: BytesMut::new(),
            cipher: Cipher::new(method, key, nonce),
            pos: 0,
            tag_size: method.tag_len(),
            steps: DecryptReadStep::Length,
            got_final: false,
        }
    }

    pub fn poll_read_decrypted<R>(
        &mut self,
        ctx: &mut Context<'_>,
        r: &mut R,
        dst: &mut ReadBuf,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncRead + Unpin,
    {
        while self.pos >= self.data.len() {
            // Already received EOF
            if self.got_final {
                return Poll::Ready(Ok(()));
            }

            // Refill buffer
            match self.steps {
                DecryptReadStep::Length => ready!(self.poll_read_decrypted_length(ctx, r))?,
                DecryptReadStep::Data(plen) => ready!(self.poll_read_decrypted_data(ctx, r, plen))?,
            }
        }

        let remaining_len = self.data.len() - self.pos;
        let n = cmp::min(dst.remaining(), remaining_len);
        dst.put_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Poll::Ready(Ok(()))
    }

    fn poll_read_decrypted_length<R>(&mut self, ctx: &mut Context<'_>, r: &mut R) -> Poll<io::Result<()>>
    where
        R: AsyncRead + Unpin,
    {
        let mlen = 2 + self.tag_size;
        ready!(self.poll_read_exact(ctx, r, mlen, true))?;
        
        if self.got_final {
            return Poll::Ready(Ok(()));
        }

        // Done reading, decrypt it
        let plen = {
            let m = &mut self.buffer[..mlen];

            if !self.cipher.decrypt_packet(m) {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, "invalid tag-in")));
            }

            u16::from_be_bytes([self.buffer[0], self.buffer[1]]) as usize
        };

        if plen > MAX_PACKET_SIZE {
            // https://shadowsocks.org/en/spec/AEAD-Ciphers.html
            //
            // AEAD TCP protocol have reserved the higher two bits for future use
            let err = io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "buffer size too large ({:#x}), AEAD encryption protocol requires buffer to be smaller than 0x3FFF, the higher two bits must be set to zero",
                    plen
                ),
            );
            return Poll::Ready(Err(err));
        }

        // Clear buffer before overwriting it
        self.buffer.clear();
        self.data.clear();
        self.pos = 0;

        // Next step, read data
        self.steps = DecryptReadStep::Data(plen);
        self.buffer.reserve(plen + self.tag_size);
        self.data.reserve(plen);

        Poll::Ready(Ok(()))
    }

    fn poll_read_decrypted_data<R>(&mut self, ctx: &mut Context<'_>, r: &mut R, plen: usize) -> Poll<io::Result<()>>
    where
        R: AsyncRead + Unpin,
    {
        let mlen = plen + self.tag_size;
        ready!(self.poll_read_exact(ctx, r, mlen, false))?;

        // Done reading data, decrypt it
        unsafe {
            let m: &mut [u8] = self.buffer.as_mut();
            assert_eq!(m.len(), mlen);

            if !self.cipher.decrypt_packet(m) {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, "invalid tag-in")));
            }

            // It has enough space, I am sure about that
            let data = slice::from_raw_parts_mut(self.data.bytes_mut().as_mut_ptr() as *mut u8, plen);
            data[..].copy_from_slice(&self.buffer[..plen]);

            // Move forward the pointer
            self.data.advance_mut(plen);
        }

        // Clear buffer before overwriting it
        self.buffer.clear();

        // Reset read position
        self.pos = 0;

        // Next step, read length
        self.steps = DecryptReadStep::Length;
        self.buffer.reserve(2 + self.tag_size);

        Poll::Ready(Ok(()))
    }

    fn poll_read_exact<R>(
        &mut self,
        ctx: &mut Context<'_>,
        r: &mut R,
        size: usize,
        allow_eof: bool,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncRead + Unpin,
    {
        let mut remaining = size - self.buffer.len();
        while remaining > 0 {
            let mut buffer = ReadBuf::uninit(&mut self.buffer.bytes_mut()[..remaining]);

            // It has enough space, I am sure about that
            ready!(Pin::new(&mut *r).poll_read(ctx, &mut buffer))?;
            let n = buffer.filled().len();
            unsafe {
                self.buffer.advance_mut(n);
            }

            if n == 0 {
                if self.buffer.is_empty() && allow_eof && !self.got_final {
                    // Read nothing
                    self.got_final = true;
                    return Poll::Ready(Ok(()));
                } else {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
            }

            remaining -= n;
        }

        Poll::Ready(Ok(()))
    }
}

enum EncryptWriteStep {
    Nothing,
    Writing,
}

/// Writer wrapper that will encrypt data automatically
pub struct EncryptedWriter {
    cipher: Cipher,
    tag_size: usize,
    steps: EncryptWriteStep,
    buf: BytesMut,
}

impl EncryptedWriter {
    /// Creates a new EncryptedWriter
    pub fn new(method: CipherKind, key: &[u8], nonce: &[u8]) -> EncryptedWriter {
        // nonce should be sent with the first packet
        let mut buf = BytesMut::with_capacity(nonce.len());
        buf.put(nonce);

        EncryptedWriter {
            cipher: Cipher::new(method, key, nonce),
            tag_size: method.tag_len(),
            steps: EncryptWriteStep::Nothing,
            buf,
        }
    }

    pub fn poll_write_encrypted<W>(
        &mut self,
        ctx: &mut Context<'_>,
        w: &mut W,
        mut data: &[u8],
    ) -> Poll<io::Result<usize>>
    where
        W: AsyncWrite + Unpin,
    {
        // Data.Len is a 16-bit big-endian integer indicating the length of Data. It must be smaller than 0x3FFF.
        if data.len() > MAX_PACKET_SIZE {
            data = &data[..MAX_PACKET_SIZE];
        }

        ready!(self.poll_write_all_encrypted(ctx, w, data))?;
        Poll::Ready(Ok(data.len()))
    }

    fn poll_write_all_encrypted<W>(&mut self, ctx: &mut Context<'_>, w: &mut W, data: &[u8]) -> Poll<io::Result<()>>
    where
        W: AsyncWrite + Unpin,
    {
        assert!(
            data.len() <= MAX_PACKET_SIZE,
            "buffer size too large, AEAD encryption protocol requires buffer to be smaller than 0x3FFF"
        );

        loop {
            match self.steps {
                EncryptWriteStep::Nothing => {
                    let plen = data.len();
                    let mlen = 2 + self.tag_size + plen + self.tag_size;

                    self.buf.reserve(mlen);

                    unsafe {
                        let len_octets = (plen as u16).to_be_bytes();
                        let m = slice::from_raw_parts_mut(self.buf.bytes_mut().as_mut_ptr() as *mut u8, mlen);
                        m[0] = len_octets[0];
                        m[1] = len_octets[1];

                        let hlen = 2 + self.tag_size;

                        m[hlen..mlen - self.tag_size].copy_from_slice(data);

                        self.cipher.encrypt_packet(&mut m[..hlen]);
                        self.cipher.encrypt_packet(&mut m[hlen..mlen]);

                        self.buf.advance_mut(mlen);
                    }

                    self.steps = EncryptWriteStep::Writing;
                }
                EncryptWriteStep::Writing => {
                    while self.buf.has_remaining() {
                        let n = ready!(Pin::new(&mut *w).poll_write(ctx, self.buf.bytes()))?;
                        self.buf.advance(n);
                        if n == 0 {
                            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                        }
                    }

                    // Reclaim buffer
                    // NOTE: This operation won't free allocated memory
                    self.buf.clear();
                    self.steps = EncryptWriteStep::Nothing;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}
