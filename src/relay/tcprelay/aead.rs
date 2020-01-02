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

use std::{
    cmp,
    io,
    marker::Unpin,
    pin::Pin,
    slice,
    task::{Context, Poll},
    u16,
};

use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, Bytes, BytesMut};
use futures::ready;
use tokio::prelude::*;

use crate::crypto::{self, BoxAeadDecryptor, BoxAeadEncryptor, CipherType};

use super::BUFFER_SIZE;

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
    cipher: BoxAeadDecryptor,
    pos: usize,
    tag_size: usize,
    steps: DecryptReadStep,
    got_final: bool,
}

impl DecryptedReader {
    pub fn new(t: CipherType, key: &[u8], nonce: &[u8]) -> DecryptedReader {
        DecryptedReader {
            buffer: BytesMut::with_capacity(BUFFER_SIZE),
            data: BytesMut::with_capacity(BUFFER_SIZE),
            cipher: crypto::new_aead_decryptor(t, key, nonce),
            pos: 0,
            tag_size: t.tag_size(),
            steps: DecryptReadStep::Length,
            got_final: false,
        }
    }

    pub fn poll_read_decrypted<R>(
        &mut self,
        ctx: &mut Context<'_>,
        r: &mut R,
        dst: &mut [u8],
    ) -> Poll<io::Result<usize>>
    where
        R: AsyncRead + Unpin,
    {
        while self.pos >= self.data.len() {
            // Already received EOF
            if self.got_final {
                return Poll::Ready(Ok(0));
            }

            // Refill buffer
            match self.steps {
                DecryptReadStep::Length => ready!(self.poll_read_decrypted_length(ctx, r))?,
                DecryptReadStep::Data(len) => ready!(self.poll_read_decrypted_data(ctx, r, len))?,
            }
        }

        let remaining_len = self.data.len() - self.pos;
        let n = cmp::min(dst.len(), remaining_len);
        (&mut dst[..n]).copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Poll::Ready(Ok(n))
    }

    fn poll_read_decrypted_length<R>(&mut self, ctx: &mut Context<'_>, r: &mut R) -> Poll<io::Result<()>>
    where
        R: AsyncRead + Unpin,
    {
        let buf_len = 2 + self.tag_size;
        ready!(self.poll_read_exact(ctx, r, buf_len, true))?;
        if self.got_final {
            return Poll::Ready(Ok(()));
        }

        // Done reading, decrypt it
        let len = {
            let mut len_buf = [0u8; 2];
            self.cipher.decrypt(&self.buffer[..], &mut len_buf)?;
            BigEndian::read_u16(&len_buf) as usize
        };

        // Clear buffer before overwriting it
        self.buffer.clear();
        self.data.clear();
        self.pos = 0;

        // Next step, read data
        self.steps = DecryptReadStep::Data(len);
        self.buffer.reserve(len + self.tag_size);
        self.data.reserve(len);

        Poll::Ready(Ok(()))
    }

    fn poll_read_decrypted_data<R>(&mut self, ctx: &mut Context<'_>, r: &mut R, size: usize) -> Poll<io::Result<()>>
    where
        R: AsyncRead + Unpin,
    {
        let buf_len = size + self.tag_size;
        ready!(self.poll_read_exact(ctx, r, buf_len, false))?;

        // Done reading data, decrypt it
        unsafe {
            // It has enough space, I am sure about that
            let buffer = slice::from_raw_parts_mut(self.data.bytes_mut().as_mut_ptr() as *mut u8, size);
            self.cipher.decrypt(&self.buffer[..], buffer)?;

            // Move forward the pointer
            self.data.advance_mut(size);
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
        while self.buffer.len() < size {
            let remaining = size - self.buffer.len();
            unsafe {
                // It has enough space, I am sure about that
                let buffer = slice::from_raw_parts_mut(self.buffer.bytes_mut().as_mut_ptr() as *mut u8, remaining);
                let n = ready!(Pin::new(&mut *r).poll_read(ctx, buffer))?;
                if n == 0 {
                    if self.buffer.is_empty() && allow_eof && !self.got_final {
                        // Read nothing
                        self.got_final = true;
                        return Poll::Ready(Ok(()));
                    } else {
                        use std::io::ErrorKind;
                        return Poll::Ready(Err(ErrorKind::UnexpectedEof.into()));
                    }
                }
                self.buffer.advance_mut(n);
            }
        }

        Poll::Ready(Ok(()))
    }
}

enum EncryptWriteStep {
    Nothing,
    Writing(BytesMut, usize),
}

/// Writer wrapper that will encrypt data automatically
pub struct EncryptedWriter {
    cipher: BoxAeadEncryptor,
    tag_size: usize,
    steps: EncryptWriteStep,
    nonce_opt: Option<Bytes>,
}

impl EncryptedWriter {
    /// Creates a new EncryptedWriter
    pub fn new(t: CipherType, key: &[u8], nonce: Bytes) -> EncryptedWriter {
        EncryptedWriter {
            cipher: crypto::new_aead_encryptor(t, key, &nonce),
            tag_size: t.tag_size(),
            steps: EncryptWriteStep::Nothing,
            nonce_opt: Some(nonce),
        }
    }

    pub fn poll_write_encrypted<W>(&mut self, ctx: &mut Context<'_>, w: &mut W, data: &[u8]) -> Poll<io::Result<usize>>
    where
        W: AsyncWrite + Unpin,
    {
        ready!(self.poll_write_all_encrypted(ctx, w, data))?;
        Poll::Ready(Ok(data.len()))
    }

    pub fn poll_write_all_encrypted<W>(&mut self, ctx: &mut Context<'_>, w: &mut W, data: &[u8]) -> Poll<io::Result<()>>
    where
        W: AsyncWrite + Unpin,
    {
        // Data.Len is a 16-bit big-endian integer indicating the length of Data. It should be smaller than 0x3FFF.
        assert!(
            data.len() <= MAX_PACKET_SIZE,
            "Buffer size too large, AEAD encryption protocol requires buffer to be smaller than 0x3FFF"
        );

        loop {
            match self.steps {
                EncryptWriteStep::Nothing => {
                    let output_length = self.buffer_size(data);
                    let data_length = data.len() as u16;

                    // First packet is IV
                    let iv_len = match self.nonce_opt {
                        Some(ref v) => v.len(),
                        None => 0,
                    };

                    let mut buf = BytesMut::with_capacity(iv_len + output_length);

                    if let Some(iv) = self.nonce_opt.take() {
                        buf.extend(iv);
                    }

                    let mut data_len_buf = [0u8; 2];
                    BigEndian::write_u16(&mut data_len_buf, data_length);

                    unsafe {
                        let b = slice::from_raw_parts_mut(buf.bytes_mut().as_mut_ptr() as *mut u8, output_length);

                        let output_length_size = 2 + self.tag_size;
                        self.cipher.encrypt(&data_len_buf, &mut b[..output_length_size]);
                        self.cipher.encrypt(data, &mut b[output_length_size..output_length]);

                        buf.advance_mut(output_length);
                    }

                    self.steps = EncryptWriteStep::Writing(buf, 0);
                }
                EncryptWriteStep::Writing(ref mut buf, ref mut pos) => {
                    while *pos < buf.len() {
                        let n = ready!(Pin::new(&mut *w).poll_write(ctx, &buf[*pos..]))?;
                        if n == 0 {
                            use std::io::ErrorKind;
                            return Poll::Ready(Err(ErrorKind::UnexpectedEof.into()));
                        }
                        *pos += n;
                    }

                    self.steps = EncryptWriteStep::Nothing;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }

    fn buffer_size(&self, data: &[u8]) -> usize {
        2 + self.tag_size // len and len_tag
        + data.len() + self.tag_size // data and data_tag
    }
}
