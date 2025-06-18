//! Shadowsocks TCP protocol

use std::io;

use bytes::BufMut;
use tokio::io::AsyncRead;

use crate::{
    crypto::{CipherCategory, CipherKind},
    relay::socks5::Address,
};

pub use self::v1::{StreamTcpRequestHeader, StreamTcpRequestHeaderRef};
#[cfg(feature = "aead-cipher-2022")]
pub use self::v2::{Aead2022TcpRequestHeader, Aead2022TcpRequestHeaderRef};

pub mod v1;
#[cfg(feature = "aead-cipher-2022")]
pub mod v2;

#[derive(Debug)]
pub enum TcpRequestHeader {
    Stream(StreamTcpRequestHeader),
    #[cfg(feature = "aead-cipher-2022")]
    Aead2022(Aead2022TcpRequestHeader),
}

impl TcpRequestHeader {
    pub async fn read_from<R: AsyncRead + Unpin>(method: CipherKind, reader: &mut R) -> io::Result<Self> {
        match method.category() {
            CipherCategory::None => Ok(Self::Stream(StreamTcpRequestHeader::read_from(reader).await?)),
            #[cfg(feature = "aead-cipher")]
            CipherCategory::Aead => Ok(Self::Stream(StreamTcpRequestHeader::read_from(reader).await?)),
            #[cfg(feature = "stream-cipher")]
            CipherCategory::Stream => Ok(Self::Stream(StreamTcpRequestHeader::read_from(reader).await?)),
            #[cfg(feature = "aead-cipher-2022")]
            CipherCategory::Aead2022 => Ok(Self::Aead2022(Aead2022TcpRequestHeader::read_from(reader).await?)),
        }
    }

    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        match *self {
            Self::Stream(ref h) => h.write_to_buf(buf),
            #[cfg(feature = "aead-cipher-2022")]
            Self::Aead2022(ref h) => h.write_to_buf(buf),
        }
    }

    pub fn addr(self) -> Address {
        match self {
            Self::Stream(h) => h.addr,
            #[cfg(feature = "aead-cipher-2022")]
            Self::Aead2022(h) => h.addr,
        }
    }

    pub fn addr_ref(&self) -> &Address {
        match *self {
            Self::Stream(ref h) => &h.addr,
            #[cfg(feature = "aead-cipher-2022")]
            Self::Aead2022(ref h) => &h.addr,
        }
    }

    pub fn serialized_len(&self) -> usize {
        match *self {
            Self::Stream(ref h) => h.serialized_len(),
            #[cfg(feature = "aead-cipher-2022")]
            Self::Aead2022(ref h) => h.serialized_len(),
        }
    }
}

#[derive(Debug)]
pub enum TcpRequestHeaderRef<'a> {
    Stream(StreamTcpRequestHeaderRef<'a>),
    #[cfg(feature = "aead-cipher-2022")]
    Aead2022(Aead2022TcpRequestHeaderRef<'a>),
}

impl TcpRequestHeaderRef<'_> {
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
