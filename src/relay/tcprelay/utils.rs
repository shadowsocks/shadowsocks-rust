//! Utility functions

use std::io;
use std::marker::Unpin;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::BUFFER_SIZE;
use crate::relay::utils::try_timeout;

pub async fn copy_timeout<R, W>(r: &mut R, w: &mut W, timeout: Option<Duration>) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; BUFFER_SIZE];

    let mut amt = 0;
    loop {
        let n = try_timeout(r.read(&mut buf), timeout).await?;
        if n == 0 {
            try_timeout(w.flush(), timeout).await?;
            break;
        }
        try_timeout(w.write_all(&buf[..n]), timeout).await?;

        amt += n as u64;
    }

    Ok(amt)
}
