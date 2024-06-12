//! HTTP Body Content-Encoding

use std::io::{self, Cursor, Read};

use futures::StreamExt;
use http::HeaderValue;
use http_body_util::BodyExt;
use hyper::body::Body;

/// HTTP Content-Encoding
#[derive(Debug, Clone, Copy, Default)]
pub enum ContentEncoding {
    #[default]
    Identity,
    Deflate,
    Gzip,
    Br,
    Zstd,
}

#[derive(Debug, Clone, Copy)]
pub struct ContentEncodingError;

impl<'a> TryFrom<&'a HeaderValue> for ContentEncoding {
    type Error = ContentEncodingError;

    fn try_from(value: &'a HeaderValue) -> Result<Self, Self::Error> {
        if value == HeaderValue::from_static("identity") {
            Ok(ContentEncoding::Identity)
        } else if value == HeaderValue::from_static("deflate") {
            Ok(ContentEncoding::Deflate)
        } else if value == HeaderValue::from_static("gzip") {
            Ok(ContentEncoding::Gzip)
        } else if value == HeaderValue::from_static("br") {
            Ok(ContentEncoding::Br)
        } else if value == HeaderValue::from_static("zstd") {
            Ok(ContentEncoding::Zstd)
        } else {
            Err(ContentEncodingError)
        }
    }
}

/// Read data from body, decode automatically with specific Content-Encoding
pub async fn read_body<B>(encoding: ContentEncoding, body: &mut B) -> io::Result<Vec<u8>>
where
    B: Body + Sized + Unpin + 'static,
    B::Data: AsRef<[u8]>,
    B::Error: Into<Box<(dyn ::std::error::Error + Send + Sync + 'static)>>,
{
    let mut raw_body = Vec::new();

    let mut body_stream = body.into_data_stream();
    while let Some(data) = body_stream.next().await {
        match data {
            Ok(data) => raw_body.extend_from_slice(data.as_ref()),
            Err(err) => return Err(io::Error::new(io::ErrorKind::Other, err)),
        }
    }

    match encoding {
        ContentEncoding::Identity => Ok(raw_body),

        ContentEncoding::Deflate => {
            use flate2::read::DeflateDecoder;

            let mut decoder = DeflateDecoder::new(&raw_body[..]);
            let mut decoded_body = Vec::new();
            decoder.read_to_end(&mut decoded_body)?;

            Ok(decoded_body)
        }

        ContentEncoding::Gzip => {
            use flate2::read::GzDecoder;

            let mut decoder = GzDecoder::new(&raw_body[..]);
            let mut decoded_body = Vec::new();
            decoder.read_to_end(&mut decoded_body)?;

            Ok(decoded_body)
        }

        ContentEncoding::Br => {
            let mut decoded_body = Vec::new();
            brotli::BrotliDecompress(&mut Cursor::new(&raw_body[..]), &mut decoded_body)?;
            Ok(decoded_body)
        }

        ContentEncoding::Zstd => zstd::decode_all(Cursor::new(&raw_body[..])),
    }
}
