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
    io::{self, ErrorKind},
    marker::Unpin,
    pin::Pin,
    slice,
    task::{Context, Poll},
    u16,
};

use bytes::{Buf, BufMut, BytesMut};
use futures::ready;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::crypto::v1::{Cipher, CipherKind};

/// AEAD packet payload must be smaller than 0x3FFF
pub const MAX_PACKET_SIZE: usize = 0x3FFF;

#[derive(Debug)]
enum DecryptReadStep {
    Init,
    Length,
    Data(usize),
    Eof,
}

/// Reader wrapper that will decrypt data automatically
pub struct DecryptedReader {
    buffer: BytesMut,
    cipher: Cipher,
    pos: usize,
    buffered: bool,
    tag_size: usize,
    steps: DecryptReadStep,
}

impl DecryptedReader {
    pub fn new(method: CipherKind, key: &[u8], nonce: &[u8]) -> DecryptedReader {
        DecryptedReader {
            buffer: BytesMut::new(),
            cipher: Cipher::new(method, key, nonce),
            pos: 0,
            buffered: false,
            tag_size: method.tag_len(),
            steps: DecryptReadStep::Init,
        }
    }

    /// Attempt to read decrypted data from reader
    ///
    /// ## Implementation Notes
    ///
    /// `DecryptedReader` will try to use `dst` to store immediate data. Any implementations that call `poll_read_decrypted` MUST-NOT
    /// modify `dst`'s underlying buffer when `Poll::Pending`.
    pub fn poll_read_decrypted<R>(
        &mut self,
        ctx: &mut Context<'_>,
        r: &mut R,
        dst: &mut ReadBuf,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncRead + Unpin,
    {
        while !self.buffered || self.pos >= self.buffer.len() {
            // Refill buffer
            match self.steps {
                DecryptReadStep::Init => {
                    // Cleanup buffer and ready for refill
                    self.buffer.clear();
                    self.pos = 0;
                    self.buffered = false;

                    let required_space = 2 + self.tag_size;
                    self.buffer.reserve(required_space);
                    self.steps = DecryptReadStep::Length;
                }
                DecryptReadStep::Length => {
                    match ready!(self.poll_read_decrypted_length_buffered(ctx, r)) {
                        Ok(plen) => {
                            // Clear buffer before overwriting it
                            self.buffer.clear();

                            // Next step, read data
                            let required_space = plen + self.tag_size;
                            self.steps = DecryptReadStep::Data(plen);
                            self.buffer.reserve(required_space);
                        }
                        Err(err) => {
                            if err.kind() == ErrorKind::UnexpectedEof && self.buffer.is_empty() {
                                self.steps = DecryptReadStep::Eof;
                            } else {
                                return Poll::Ready(Err(err));
                            }
                        }
                    };
                }
                DecryptReadStep::Data(plen) => ready!(self.poll_read_decrypted_data_buffered(ctx, r, plen))?,
                DecryptReadStep::Eof => return Poll::Ready(Ok(())),
            }
        }

        let remaining_len = self.buffer.len() - self.pos;
        let n = cmp::min(dst.remaining(), remaining_len);
        dst.put_slice(&self.buffer[self.pos..self.pos + n]);
        self.pos += n;

        Poll::Ready(Ok(()))
    }

    fn poll_read_decrypted_length_buffered<R>(&mut self, ctx: &mut Context<'_>, r: &mut R) -> Poll<io::Result<usize>>
    where
        R: AsyncRead + Unpin,
    {
        let mlen = 2 + self.tag_size;
        ready!(self.poll_read_exact_buffered(ctx, r, mlen))?;

        // Done reading, decrypt it
        let plen = DecryptedReader::decrypt_length(&mut self.cipher, &mut self.buffer[..mlen])?;
        Poll::Ready(Ok(plen))
    }

    fn poll_read_decrypted_data_buffered<R>(
        &mut self,
        ctx: &mut Context<'_>,
        r: &mut R,
        plen: usize,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncRead + Unpin,
    {
        let mlen = plen + self.tag_size;
        ready!(self.poll_read_exact_buffered(ctx, r, mlen))?;

        // Done reading data, decrypt it
        let m: &mut [u8] = self.buffer.as_mut();
        assert_eq!(m.len(), mlen);

        if !self.cipher.decrypt_packet(m) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, "invalid tag-in")));
        }

        // self.buffer[..plen] stores decrypted data
        self.buffer.truncate(plen);
        self.buffered = true;

        // Next step, read length
        self.steps = DecryptReadStep::Init;

        Poll::Ready(Ok(()))
    }

    fn poll_read_exact_buffered<R>(&mut self, ctx: &mut Context<'_>, r: &mut R, size: usize) -> Poll<io::Result<()>>
    where
        R: AsyncRead + Unpin,
    {
        let mut remaining = size - self.buffer.len();
        while remaining > 0 {
            let raw_buffer = &mut self.buffer.bytes_mut()[..remaining];
            assert_eq!(raw_buffer.len(), remaining);

            let mut buffer =
                unsafe { ReadBuf::uninit(slice::from_raw_parts_mut(raw_buffer.as_mut_ptr() as *mut _, remaining)) };

            // It has enough space, I am sure about that
            ready!(Pin::new(&mut *r).poll_read(ctx, &mut buffer))?;
            let n = buffer.filled().len();
            unsafe {
                self.buffer.advance_mut(n);
            }

            if n == 0 {
                return Poll::Ready(Err(ErrorKind::UnexpectedEof.into()));
            }

            remaining -= n;
        }

        Poll::Ready(Ok(()))
    }

    fn decrypt_length(cipher: &mut Cipher, m: &mut [u8]) -> io::Result<usize> {
        let plen = {
            if !cipher.decrypt_packet(m) {
                return Err(io::Error::new(ErrorKind::Other, "invalid tag-in"));
            }

            u16::from_be_bytes([m[0], m[1]]) as usize
        };

        if plen > MAX_PACKET_SIZE {
            // https://shadowsocks.org/en/spec/AEAD-Ciphers.html
            //
            // AEAD TCP protocol have reserved the higher two bits for future use
            let err = io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "buffer size too large ({:#x}), AEAD encryption protocol requires buffer to be smaller than 0x3FFF, the higher two bits must be set to zero",
                    plen
                ),
            );
            return Err(err);
        }

        Ok(plen)
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
