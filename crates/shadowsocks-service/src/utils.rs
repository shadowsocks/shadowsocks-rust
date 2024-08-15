//! Service Utilities

use std::{
    future::Future,
    io::{self, ErrorKind},
    pin::Pin,
    task::{Context, Poll},
};

use futures::ready;
use tokio::task::JoinHandle;

/// Wrapper of `tokio::task::JoinHandle`, which links to a server instance.
///
/// `ServerHandle` implements `Future` which will join the `JoinHandle` and get the result.
/// When `ServerHandle` drops, it will abort the task.
pub struct ServerHandle(pub JoinHandle<io::Result<()>>);

impl Drop for ServerHandle {
    #[inline]
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Future for ServerHandle {
    type Output = io::Result<()>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match ready!(Pin::new(&mut self.0).poll(cx)) {
            Ok(res) => res.into(),
            Err(err) => Err(io::Error::new(ErrorKind::Other, err)).into(),
        }
    }
}
