//! Shadowsocks TCP protocol

use std::io;

use bytes::BufMut;
use tokio::io::AsyncRead;

use crate::{
    crypto::{CipherCategory, CipherKind},
    relay::socks5::Address,
};

pub use self::v1::{
    StreamTcpRequestHeader,
    StreamTcpRequestHeaderRef,
    StreamTcpResponseHeader,
    StreamTcpResponseHeaderRef,
};
#[cfg(feature = "aead-cipher-2022")]
pub use self::v2::{
    Aead2022TcpRequestHeader,
    Aead2022TcpRequestHeaderRef,
    Aead2022TcpResponseHeader,
    Aead2022TcpResponseHeaderRef,
};

pub mod v1;
#[cfg(feature = "aead-cipher-2022")]
pub mod v2;

pub enum TcpRequestHeader {
    Stream(StreamTcpRequestHeader),
    #[cfg(feature = "aead-cipher-2022")]
    Aead2022(Aead2022TcpRequestHeader),
}

impl TcpRequestHeader {
    pub async fn read_from<R: AsyncRead + Unpin>(method: CipherKind, reader: &mut R) -> io::Result<TcpRequestHeader> {
        match method.category() {
            CipherCategory::None | CipherCategory::Aead => Ok(TcpRequestHeader::Stream(
                StreamTcpRequestHeader::read_from(reader).await?,
            )),
            #[cfg(feature = "stream-cipher")]
            CipherCategory::Stream => Ok(TcpRequestHeader::Stream(
                StreamTcpRequestHeader::read_from(reader).await?,
            )),
            #[cfg(feature = "aead-cipher-2022")]
            CipherCategory::Aead2022 => Ok(TcpRequestHeader::Aead2022(
                Aead2022TcpRequestHeader::read_from(reader).await?,
            )),
        }
    }

    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        match *self {
            TcpRequestHeader::Stream(ref h) => h.write_to_buf(buf),
            #[cfg(feature = "aead-cipher-2022")]
            TcpRequestHeader::Aead2022(ref h) => h.write_to_buf(buf),
        }
    }

    pub fn addr(self) -> Address {
        match self {
            TcpRequestHeader::Stream(h) => h.addr,
            #[cfg(feature = "aead-cipher-2022")]
            TcpRequestHeader::Aead2022(h) => h.addr,
        }
    }

    pub fn addr_ref(&self) -> &Address {
        match *self {
            TcpRequestHeader::Stream(ref h) => &h.addr,
            #[cfg(feature = "aead-cipher-2022")]
            TcpRequestHeader::Aead2022(ref h) => &h.addr,
        }
    }

    pub fn serialized_len(&self) -> usize {
        match *self {
            TcpRequestHeader::Stream(ref h) => h.serialized_len(),
            #[cfg(feature = "aead-cipher-2022")]
            TcpRequestHeader::Aead2022(ref h) => h.serialized_len(),
        }
    }
}

pub enum TcpRequestHeaderRef<'a> {
    Stream(StreamTcpRequestHeaderRef<'a>),
    #[cfg(feature = "aead-cipher-2022")]
    Aead2022(Aead2022TcpRequestHeaderRef<'a>),
}

impl<'a> TcpRequestHeaderRef<'a> {
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        match *self {
            TcpRequestHeaderRef::Stream(ref h) => h.write_to_buf(buf),
            #[cfg(feature = "aead-cipher-2022")]
            TcpRequestHeaderRef::Aead2022(ref h) => h.write_to_buf(buf),
        }
    }

    pub fn serialized_len(&self) -> usize {
        match *self {
            TcpRequestHeaderRef::Stream(ref h) => h.serialized_len(),
            #[cfg(feature = "aead-cipher-2022")]
            TcpRequestHeaderRef::Aead2022(ref h) => h.serialized_len(),
        }
    }
}

pub enum TcpResponseHeader {
    Stream(StreamTcpResponseHeader),
    #[cfg(feature = "aead-cipher-2022")]
    Aead2022(Aead2022TcpResponseHeader),
}

impl TcpResponseHeader {
    pub async fn read_from<R: AsyncRead + Unpin>(method: CipherKind, reader: &mut R) -> io::Result<TcpResponseHeader> {
        match method.category() {
            CipherCategory::None | CipherCategory::Aead => Ok(TcpResponseHeader::Stream(
                StreamTcpResponseHeader::read_from(reader).await?,
            )),
            #[cfg(feature = "stream-cipher")]
            CipherCategory::Stream => Ok(TcpResponseHeader::Stream(
                StreamTcpResponseHeader::read_from(reader).await?,
            )),
            #[cfg(feature = "aead-cipher-2022")]
            CipherCategory::Aead2022 => Ok(TcpResponseHeader::Aead2022(
                Aead2022TcpResponseHeader::read_from(method, reader).await?,
            )),
        }
    }

    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        match *self {
            TcpResponseHeader::Stream(ref h) => h.write_to_buf(buf),
            #[cfg(feature = "aead-cipher-2022")]
            TcpResponseHeader::Aead2022(ref h) => h.write_to_buf(buf),
        }
    }

    pub fn serialized_len(&self) -> usize {
        match *self {
            TcpResponseHeader::Stream(ref h) => h.serialized_len(),
            #[cfg(feature = "aead-cipher-2022")]
            TcpResponseHeader::Aead2022(ref h) => h.serialized_len(),
        }
    }
}

pub enum TcpResponseHeaderRef<'a> {
    Stream(StreamTcpResponseHeaderRef<'a>),
    #[cfg(feature = "aead-cipher-2022")]
    Aead2022(Aead2022TcpResponseHeaderRef<'a>),
}

impl<'a> TcpResponseHeaderRef<'a> {
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        match *self {
            TcpResponseHeaderRef::Stream(ref h) => h.write_to_buf(buf),
            #[cfg(feature = "aead-cipher-2022")]
            TcpResponseHeaderRef::Aead2022(ref h) => h.write_to_buf(buf),
        }
    }

    pub fn serialized_len(&self) -> usize {
        match *self {
            TcpResponseHeaderRef::Stream(ref h) => h.serialized_len(),
            #[cfg(feature = "aead-cipher-2022")]
            TcpResponseHeaderRef::Aead2022(ref h) => h.serialized_len(),
        }
    }
}
