use futures::{
    future::{self, Either},
    StreamExt,
};
use log::info;
use std::io;
use tokio::signal::unix::{signal, SignalKind};

pub async fn create_signal_monitor() -> io::Result<()> {
    // Future resolving to two signal streams. Can fail if setting up signal monitoring fails
    let sigterm = signal(SignalKind::terminate())?;
    let sigint = signal(SignalKind::interrupt())?;

    let signal_name = match future::select(sigterm.into_future(), sigint.into_future()).await {
        Either::Left(..) => "SIGTERM",
        Either::Right(..) => "SIGINT",
    };

    info!("Received {}, exiting", signal_name);

    Ok(())
}
