use std::{io, time::Duration};

use tokio::prelude::*;

pub async fn try_timeout<T, E, F>(fut: F, timeout: Option<Duration>) -> io::Result<T>
where
    F: Future<Output = Result<T, E>>,
    io::Error: From<E>,
{
    match timeout {
        Some(t) => fut.timeout(t).await?,
        None => fut.await,
    }
    .map_err(From::from)
}
