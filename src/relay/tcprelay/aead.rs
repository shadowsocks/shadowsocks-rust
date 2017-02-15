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

use std::io::{self, Read, Write, BufRead, Cursor};
use std::cmp;
use std::u16;

use byteorder::{BigEndian, WriteBytesExt};

use crypto::{self, CipherType, AeadEncryptor, AeadDecryptor};

use super::{EncryptedWrite, DecryptedRead, BUFFER_SIZE};

enum ReadingStep {
    DataLength,
    DataAndTag(usize),
    DataDone,
}

/// Reader wrapper that will decrypt data automatically
pub struct DecryptedReader<R>
    where R: Read
{
    reader: R,
    buffer: Vec<u8>,
    data: Vec<u8>,
    cipher: Box<AeadDecryptor>,
    pos: usize,
    sent_final: bool,
    tag_size: usize,
    read_step: ReadingStep,
}

impl<R> DecryptedReader<R>
    where R: Read
{
    pub fn new(r: R, t: CipherType, key: &[u8], nounce: &[u8]) -> DecryptedReader<R> {
        DecryptedReader {
            reader: r,
            buffer: Vec::new(),
            data: Vec::new(),
            cipher: crypto::new_aead_decryptor(t, key, nounce),
            pos: 0,
            sent_final: false,
            tag_size: t.tag_size(),
            read_step: ReadingStep::DataLength,
        }
    }

    pub fn get_ref(&self) -> &R {
        &self.reader
    }

    /// Gets a mutable reference to the underlying reader.
    ///
    /// # Warning
    ///
    /// It is inadvisable to read directly from or write directly to the
    /// underlying reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.reader
    }

    /// Unwraps this `DecryptedReader`, returning the underlying reader.
    ///
    /// The internal buffer is flushed before returning the reader. Any leftover
    /// data in the read buffer is lost.
    pub fn into_inner(self) -> R {
        self.reader
    }

    fn read_exact(&mut self, expect_length: usize, ignore_final: bool) -> io::Result<()> {
        let mut incoming = [0u8; BUFFER_SIZE];

        while self.buffer.len() < expect_length {
            let remain = expect_length - self.buffer.len();
            let rlen = cmp::min(remain, incoming.len());
            match self.reader.read(&mut incoming[..rlen]) {
                Ok(0) => {
                    if ignore_final && self.buffer.is_empty() {
                        self.sent_final = true;
                        return Ok(());
                    }

                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected eof"));
                }
                Ok(n) => self.buffer.extend_from_slice(&incoming[..n]),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn read_length(&mut self) -> io::Result<()> {
        let expect_length = 2 + self.tag_size;
        self.read_exact(expect_length, true)?;

        if !self.sent_final {
            // Ok, read length finished
            {
                let data = &self.buffer[..2];
                let tag = &self.buffer[2..];
                let mut len_buf = [0u8; 2];
                self.cipher.decrypt(data, &mut len_buf, tag)?;

                let len = ((len_buf[0] as u16) << 8) | (len_buf[1] as u16);
                self.read_step = ReadingStep::DataAndTag(u16::from_be(len) as usize);
            }
            self.buffer.clear();
        }

        Ok(())
    }

    fn read_data(&mut self, dlen: usize) -> io::Result<()> {
        let expect_length = dlen + self.tag_size;
        self.read_exact(expect_length, false)?;

        if !self.sent_final {
            {
                // Ok, got data
                let data = &self.buffer[..dlen];
                let tag = &self.buffer[dlen..];
                self.data.resize(dlen, 0);
                self.cipher.decrypt(data, &mut self.data, tag)?;
            }

            self.read_step = ReadingStep::DataDone;
            self.buffer.clear();
        }

        Ok(())
    }

    fn read_some(&mut self) -> io::Result<()> {
        while !self.sent_final {
            match self.read_step {
                ReadingStep::DataLength => self.read_length()?,
                ReadingStep::DataAndTag(dlen) => self.read_data(dlen)?,
                ReadingStep::DataDone => self.read_step = ReadingStep::DataLength,
            }
        }
        Ok(())
    }
}

impl<R> BufRead for DecryptedReader<R>
    where R: Read
{
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        while self.pos >= self.data.len() {
            if self.sent_final {
                return Ok(&[]);
            }

            self.read_some()?;
            if let ReadingStep::DataDone = self.read_step {
                self.pos = 0;
            }
        }

        Ok(&self.data[self.pos..])
    }

    fn consume(&mut self, amt: usize) {
        self.pos = cmp::min(self.pos + amt, self.buffer.len());
    }
}

impl<R> Read for DecryptedReader<R>
    where R: Read
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let nread = {
            let mut available = try!(self.fill_buf());
            try!(available.read(buf))
        };
        self.consume(nread);
        Ok(nread)
    }
}

impl<R> DecryptedRead for DecryptedReader<R> where R: Read {}

/// Writer wrapper that will encrypt data automatically
pub struct EncryptedWriter<W>
    where W: Write
{
    writer: W,
    cipher: Box<AeadEncryptor>,
    tag_size: usize,
}

impl<W> EncryptedWriter<W>
    where W: Write
{
    /// Creates a new EncryptedWriter
    pub fn new(w: W, t: CipherType, key: &[u8], nounce: &[u8]) -> EncryptedWriter<W> {
        EncryptedWriter {
            writer: w,
            cipher: crypto::new_aead_encryptor(t, key, nounce),
            tag_size: t.tag_size(),
        }
    }
}

impl<W> EncryptedWrite for EncryptedWriter<W>
    where W: Write
{
    fn write_raw(&mut self, data: &[u8]) -> io::Result<usize> {
        self.writer.write(data)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }

    fn encrypt(&mut self, data: &[u8], buf: &mut Vec<u8>) -> io::Result<()> {
        // Data.Len is a 16-bit big-endian integer indicating the length of Data. It should be smaller than 0x3FFF.
        assert!(data.len() <= 0x3FFF);

        let data_length = data.len() as u16;

        let mut data_len_buf = [0u8; 2];
        {
            let mut cur = Cursor::new(&mut data_len_buf[..]);
            let _ = cur.write_u16::<BigEndian>(data_length);
        }

        let mut tag_buf = vec![0u8; self.tag_size];

        let mut encrypted_data_len = [0u8; 2];
        self.cipher.encrypt(&data_len_buf[..], &mut encrypted_data_len, &mut tag_buf[..]);

        buf.extend_from_slice(&encrypted_data_len);
        buf.extend_from_slice(&tag_buf);

        let orig_buf_len = buf.len();
        buf.reserve(data.len() + self.tag_size);
        buf.resize(orig_buf_len + data.len(), 0);
        self.cipher.encrypt(data, &mut buf[orig_buf_len..], &mut tag_buf);
        buf.append(&mut tag_buf);

        Ok(())
    }
}