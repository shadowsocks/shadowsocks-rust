use std::{
    future::Future,
    io::{self, Error},
    time::Duration,
};

use tokio::time;

pub async fn try_timeout<T, E, F>(fut: F, timeout: Option<Duration>) -> io::Result<T>
where
    F: Future<Output = Result<T, E>>,
    Error: From<E>,
{
    match timeout {
        Some(t) => time::timeout(t, fut).await?,
        None => fut.await,
    }
    .map_err(From::from)
}
