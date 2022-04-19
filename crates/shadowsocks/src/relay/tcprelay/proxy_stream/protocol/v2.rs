//! Shadowsocks AEAD 2022 header protocol

use std::{
    io::{self, ErrorKind},
    time::SystemTime,
};

use bytes::BufMut;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::{crypto::CipherKind, relay::Address};

pub const MAX_PADDING_SIZE: usize = 900;
pub const SERVER_STREAM_TIMESTAMP_MAX_DIFF: u64 = 30;

#[inline]
pub fn get_now_timestamp() -> u64 {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => panic!("SystemTime::now() is before UNIX Epoch!"),
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aead2022TcpStreamType {
    Client = 0,
    Server = 1,
}

/// TCP Request Header
//
/// +-------+-------+-------+-------+-------+-------+-------+-------+-------+
/// | TYPE  | UNIX TIMESTAMP                                                |
/// +-------+-------+-------+-------+-------+-------+-------+-------+-------+
/// | ADDR (Variable ...)
/// +-------+-------+-------+-------+-------+-------+-------+-------+-------+
/// | PADDING SIZE  | PADDING (Variable ...)
/// +-------+-------+-------+-------+-------+-------+-------+-------+-------+
#[derive(Debug, Clone)]
pub struct Aead2022TcpRequestHeader {
    pub addr: Address,
    pub timestamp: u64,
    pub padding_size: u16,
}

impl Aead2022TcpRequestHeader {
    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Aead2022TcpRequestHeader> {
        use std::slice;

        let mut fix_header1 = [0u8; 1 + 8];
        reader.read_exact(&mut fix_header1).await?;

        let stream_type = fix_header1[0];
        if stream_type != Aead2022TcpStreamType::Client as u8 {
            return Err(io::Error::new(
                ErrorKind::Other,
                format!("TCP request type {} invalid", stream_type),
            ));
        }

        let timestamp_slice = &fix_header1[1..];
        let timestamp_buffer: &[u64] = unsafe { slice::from_raw_parts(timestamp_slice.as_ptr() as *const _, 1) };
        let timestamp = u64::from_be(timestamp_buffer[0]);

        let now = get_now_timestamp();

        if now.abs_diff(timestamp) > SERVER_STREAM_TIMESTAMP_MAX_DIFF {
            return Err(io::Error::new(
                ErrorKind::Other,
                format!("received TCP request header with aged timestamp: {}", timestamp),
            ));
        }

        let addr = Address::read_from(reader).await?;

        let mut padding_size_buffer = [0u8; 2];
        reader.read_exact(&mut padding_size_buffer).await?;

        let padding_size = u16::from_be_bytes(padding_size_buffer);
        if padding_size > 0 {
            let mut take_reader = reader.take(padding_size as u64);
            let mut buffer = [0u8; 64];
            loop {
                match take_reader.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(..) => continue,
                    Err(err) => return Err(err),
                }
            }
        }

        Ok(Aead2022TcpRequestHeader {
            addr,
            timestamp,
            padding_size,
        })
    }

    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        Aead2022TcpRequestHeaderRef {
            addr: &self.addr,
            timestamp: self.timestamp,
            padding_size: self.padding_size,
        }
        .write_to_buf(buf)
    }

    pub fn serialized_len(&self) -> usize {
        Aead2022TcpRequestHeaderRef {
            addr: &self.addr,
            timestamp: self.timestamp,
            padding_size: self.padding_size,
        }
        .serialized_len()
    }
}

pub struct Aead2022TcpRequestHeaderRef<'a> {
    pub addr: &'a Address,
    pub timestamp: u64,
    pub padding_size: u16,
}

impl<'a> Aead2022TcpRequestHeaderRef<'a> {
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(Aead2022TcpStreamType::Client as u8);
        buf.put_u64(self.timestamp);
        self.addr.write_to_buf(buf);

        assert!(
            self.padding_size as usize <= MAX_PADDING_SIZE,
            "padding length must be in [0, {}]",
            MAX_PADDING_SIZE
        );

        buf.put_u16(self.padding_size);
        if self.padding_size > 0 {
            unsafe {
                buf.advance_mut(self.padding_size as usize);
            }
        }
    }

    pub fn serialized_len(&self) -> usize {
        1 + 8 + self.addr.serialized_len() + 2 + self.padding_size as usize
    }
}

/// AEAD 2022 TCP Response Header
///
/// +-------+-------+-------+-------+-------+-------+-------+-------+-------+
/// | TYPE  | UNIX TIMESTAMP                                                |
/// +-------+-------+-------+-------+-------+-------+-------+-------+-------+
/// | Request SALT (Variable ...)
/// +-------+-------+-------+-------+-------+-------+-------+-------+-------+
pub struct Aead2022TcpResponseHeader {
    pub timestamp: u64,
    pub request_salt: Vec<u8>,
}

impl Aead2022TcpResponseHeader {
    pub async fn read_from<R: AsyncRead + Unpin>(
        method: CipherKind,
        reader: &mut R,
    ) -> io::Result<Aead2022TcpResponseHeader> {
        use std::slice;

        let mut fix_header1 = [0u8; 1 + 8];
        reader.read_exact(&mut fix_header1).await?;

        let stream_type = fix_header1[0];
        if stream_type != Aead2022TcpStreamType::Server as u8 {
            return Err(io::Error::new(
                ErrorKind::Other,
                format!("TCP request type {} invalid", stream_type),
            ));
        }

        let timestamp_slice = &fix_header1[1..];
        let timestamp_buffer: &[u64] = unsafe { slice::from_raw_parts(timestamp_slice.as_ptr() as *const _, 1) };
        let timestamp = u64::from_be(timestamp_buffer[0]);

        let now = get_now_timestamp();

        if now.abs_diff(timestamp) > SERVER_STREAM_TIMESTAMP_MAX_DIFF {
            return Err(io::Error::new(
                ErrorKind::Other,
                format!("received TCP response header with aged timestamp: {}", timestamp),
            ));
        }

        let salt_size = method.salt_len();
        let mut request_salt = vec![0u8; salt_size];
        reader.read_exact(&mut request_salt).await?;

        Ok(Aead2022TcpResponseHeader {
            timestamp,
            request_salt,
        })
    }

    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        Aead2022TcpResponseHeaderRef {
            timestamp: self.timestamp,
            request_salt: &self.request_salt,
        }
        .write_to_buf(buf)
    }

    pub fn serialized_len(&self) -> usize {
        Aead2022TcpResponseHeaderRef {
            timestamp: self.timestamp,
            request_salt: &self.request_salt,
        }
        .serialized_len()
    }
}

pub struct Aead2022TcpResponseHeaderRef<'a> {
    pub timestamp: u64,
    pub request_salt: &'a [u8],
}

impl<'a> Aead2022TcpResponseHeaderRef<'a> {
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(Aead2022TcpStreamType::Server as u8);
        buf.put_u64(self.timestamp);
        buf.put_slice(self.request_salt);
    }

    pub fn serialized_len(&self) -> usize {
        1 + 8 + self.request_salt.len()
    }
}
