use futures::{self, Either};
use log::info;
use std::io;
use tokio::signal::{ctrl_c, windows::ctrl_break};

pub async fn create_signal_monitor() -> io::Result<()> {
    let cc = ctrl_c()?;
    let cb = ctrl_break()?;

    let signal_name = match future::select(cc.into_future(), cb.into_future()).await {
        Either::Left(..) => "CTRL-C",
        Either::Right(..) => "CTRL-BREAK",
    };

    info!("Received {}, exiting", signal_name);

    Ok(())
}
