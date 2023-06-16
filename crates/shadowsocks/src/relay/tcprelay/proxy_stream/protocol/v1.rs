//! Shadowsocks Stream / AEAD header protocol

use std::io;

use bytes::BufMut;
use tokio::io::AsyncRead;

use crate::relay::socks5::Address;

pub struct StreamTcpRequestHeader {
    pub addr: Address,
}

impl StreamTcpRequestHeader {
    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<StreamTcpRequestHeader> {
        Ok(StreamTcpRequestHeader {
            addr: Address::read_from(reader).await?,
        })
    }

    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        StreamTcpRequestHeaderRef { addr: &self.addr }.write_to_buf(buf)
    }

    pub fn serialized_len(&self) -> usize {
        StreamTcpRequestHeaderRef { addr: &self.addr }.serialized_len()
    }
}

pub struct StreamTcpRequestHeaderRef<'a> {
    pub addr: &'a Address,
}

impl<'a> StreamTcpRequestHeaderRef<'a> {
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        self.addr.write_to_buf(buf);
    }

    pub fn serialized_len(&self) -> usize {
        self.addr.serialized_len()
    }
}
