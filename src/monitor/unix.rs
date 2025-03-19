use futures::future::{self, Either, FutureExt};
use log::info;
use std::io;
use tokio::signal::unix::{SignalKind, signal};

/// Create a monitor future for signals
///
/// It will exit when received `SIGTERM` or `SIGINT`.
pub async fn create_signal_monitor() -> io::Result<()> {
    // Future resolving to two signal streams. Can fail if setting up signal monitoring fails
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    let signal_name = match future::select(sigterm.recv().boxed(), sigint.recv().boxed()).await {
        Either::Left(..) => "SIGTERM",
        Either::Right(..) => "SIGINT",
    };

    info!("received {}, exiting", signal_name);

    Ok(())
}
