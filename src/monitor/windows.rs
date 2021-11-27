use log::info;
use std::io;
use tokio::signal::ctrl_c;

/// Create a monitor future for signals
///
/// It will exit when received Ctrl-C.
pub async fn create_signal_monitor() -> io::Result<()> {
    let _ = ctrl_c().await;
    info!("received CTRL-C, exiting");

    Ok(())
}
