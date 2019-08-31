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
    io::{self, BufRead, Read},
    marker::Unpin,
    pin::Pin,
    task::{Context, Poll},
    u16,
};

use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use log::error;
use tokio::prelude::*;

use crate::crypto::{self, BoxAeadDecryptor, BoxAeadEncryptor, CipherType};

use super::{DecryptedRead, EncryptedWrite, BUFFER_SIZE};

/// AEAD packet payload must be smaller than 0x3FFF
const MAX_PACKET_SIZE: usize = 0x3FFF;

enum ReadingStep {
    Length,
    DataAndTag(usize),
    Done,
}

/// Reader wrapper that will decrypt data automatically
pub struct DecryptedReader<R> {
    reader: R,
    buffer: BytesMut,
    data: BytesMut,
    cipher: BoxAeadDecryptor,
    pos: usize,
    sent_final: bool,
    tag_size: usize,
    read_step: ReadingStep,
}

// Forward Unpin
impl<A: Unpin> Unpin for DecryptedReader<A> {}

impl<R> DecryptedReader<R> {
    pub fn new(r: R, t: CipherType, key: &[u8], nounce: &[u8]) -> DecryptedReader<R> {
        DecryptedReader {
            reader: r,
            buffer: BytesMut::with_capacity(BUFFER_SIZE),
            data: BytesMut::with_capacity(BUFFER_SIZE),
            cipher: crypto::new_aead_decryptor(t, key, nounce),
            pos: 0,
            sent_final: false,
            tag_size: t.tag_size(),
            read_step: ReadingStep::Length,
        }
    }
}

impl<R> DecryptedReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read_exact(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        expect_length: usize,
        ignore_final: bool,
    ) -> Poll<io::Result<()>> {
        let mut incoming = [0u8; BUFFER_SIZE];
        self.buffer.reserve(expect_length);

        while self.buffer.len() < expect_length {
            let remain = expect_length - self.buffer.len();
            let rlen = cmp::min(remain, incoming.len());

            let n = match Pin::new(&mut self.reader).poll_read(cx, &mut incoming[..rlen])? {
                Poll::Ready(n) => n,
                Poll::Pending => return Poll::Pending,
            };

            if n == 0 {
                if ignore_final && self.buffer.is_empty() {
                    self.sent_final = true;
                    return Poll::Ready(Ok(()));
                }

                return Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected eof")));
            } else {
                self.buffer.put_slice(&incoming[..n])
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_read_length(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let expect_length = 2 + self.tag_size;
        match self.poll_read_exact(cx, expect_length, true)? {
            Poll::Ready(..) => (),
            Poll::Pending => return Poll::Pending,
        }

        if !self.sent_final {
            // Ok, read length finished
            {
                let len = {
                    let mut len_buf = [0u8; 2];
                    self.cipher.decrypt(&self.buffer[..], &mut len_buf)?;
                    BigEndian::read_u16(&len_buf) as usize
                };

                if len > MAX_PACKET_SIZE {
                    use std::io::{Error, ErrorKind};

                    error!(
                        "AEAD packet size must be <= {}, but received length {}",
                        MAX_PACKET_SIZE, len
                    );

                    let err = Error::new(
                        ErrorKind::InvalidData,
                        format!(
                            "AEAD packet size must be <= {}, but received length {}",
                            MAX_PACKET_SIZE, len
                        ),
                    );
                    return Poll::Ready(Err(err));
                }

                self.read_step = ReadingStep::DataAndTag(len);
            }
            self.buffer.clear();
        }

        Poll::Ready(Ok(()))
    }

    fn poll_read_data(self: Pin<&mut Self>, cx: &mut Context<'_>, dlen: usize) -> Poll<io::Result<()>> {
        let expect_length = dlen + self.tag_size;
        match self.poll_read_exact(cx, expect_length, false)? {
            Poll::Ready(..) => (),
            Poll::Pending => return Poll::Pending,
        }

        if !self.sent_final {
            {
                // Ok, got data
                self.data.clear();
                self.data.reserve(dlen);
                unsafe {
                    self.data.set_len(dlen); // Decrypted data has exactly the same length
                }
                self.cipher.decrypt(&self.buffer[..], &mut *self.data)?;
            }

            self.read_step = ReadingStep::Done;
            self.buffer.clear();
        }

        Poll::Ready(Ok(()))
    }

    fn poll_read_some(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.sent_final {
            match self.read_step {
                ReadingStep::Length => match self.poll_read_length(cx)? {
                    Poll::Ready(..) => (),
                    Poll::Pending => return Poll::Pending,
                },
                ReadingStep::DataAndTag(dlen) => {
                    match self.poll_read_data(cx, dlen)? {
                        Poll::Ready(..) => (),
                        Poll::Pending => return Poll::Pending,
                    }
                    break; // Read finished! Break out
                }
                ReadingStep::Done => {
                    self.read_step = ReadingStep::Length;
                    self.data.clear();
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<R> AsyncBufRead for DecryptedReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        while self.pos >= self.data.len() {
            if self.sent_final {
                return Poll::Ready(Ok(&[]));
            }

            match self.poll_read_some(cx)? {
                Poll::Ready(..) => (),
                Poll::Pending => return Poll::Pending,
            }

            if let ReadingStep::Done = self.read_step {
                self.pos = 0;
            }
        }

        Poll::Ready(Ok(&self.data[self.pos..]))
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        self.pos = cmp::min(self.pos + amt, self.data.len());
    }
}

impl<R> AsyncRead for DecryptedReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let nread = {
            let mut available = match self.poll_fill_buf(cx)? {
                Poll::Ready(a) => a,
                Poll::Pending => return Poll::Pending,
            };

            let len = available.len().min(buf.len());
            buf.copy_from_slice(&available[..len]);
            len
        };
        self.consume(nread);
        Poll::Ready(Ok(nread))
    }
}

impl<R> DecryptedRead for DecryptedReader<R> {
    fn buffer_size(&self, data: &[u8]) -> usize {
        2 + self.tag_size // len and len_tag
        + data.len() + self.tag_size // data and data_tag
    }
}

/// Writer wrapper that will encrypt data automatically
pub struct EncryptedWriter<W> {
    writer: W,
    cipher: BoxAeadEncryptor,
    tag_size: usize,
}

impl<W> EncryptedWriter<W> {
    /// Creates a new EncryptedWriter
    pub fn new(w: W, t: CipherType, key: &[u8], nonce: &[u8]) -> EncryptedWriter<W> {
        EncryptedWriter {
            writer: w,
            cipher: crypto::new_aead_encryptor(t, key, nonce),
            tag_size: t.tag_size(),
        }
    }
}

// Forward Unpin
impl<A: Unpin> Unpin for EncryptedWriter<A> {}

impl<W> AsyncWrite for EncryptedWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

impl<W> EncryptedWrite for EncryptedWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn encrypt<B: BufMut>(&mut self, data: &[u8], buf: &mut B) -> io::Result<()> {
        // Data.Len is a 16-bit big-endian integer indicating the length of Data. It should be smaller than 0x3FFF.
        assert!(
            data.len() <= MAX_PACKET_SIZE,
            "Buffer size too large, AEAD encryption protocol requires buffer to be smaller than 0x3FFF"
        );

        let output_length = self.buffer_size(data);
        let data_length = data.len() as u16;

        let mut data_len_buf = [0u8; 2];
        BigEndian::write_u16(&mut data_len_buf, data_length);

        let output_length_size = 2 + self.tag_size;
        self.cipher
            .encrypt(&data_len_buf, unsafe { &mut buf.bytes_mut()[..output_length_size] });
        self.cipher
            .encrypt(data, unsafe { &mut buf.bytes_mut()[output_length_size..output_length] });

        unsafe {
            buf.advance_mut(output_length);
        }

        Ok(())
    }

    fn buffer_size(&self, data: &[u8]) -> usize {
        2 + self.tag_size // len and len_tag
        + data.len() + self.tag_size // data and data_tag
    }
}
