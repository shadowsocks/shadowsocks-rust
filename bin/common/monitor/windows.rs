use log::info;
use std::io;
use tokio::signal::ctrl_c;

pub async fn create_signal_monitor() -> io::Result<()> {
    ctrl_c().await;
    info!("received CTRL-C, exiting");

    Ok(())
}
