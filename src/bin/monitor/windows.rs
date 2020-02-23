use futures::{
    future::{self, Either, FutureExt},
    StreamExt,
};
use log::info;
use std::io;
use tokio::signal::{ctrl_c, windows::ctrl_break};

pub async fn create_signal_monitor() -> io::Result<()> {
    let cc = ctrl_c();
    let cb = ctrl_break()?;

    let signal_name = match future::select(cc.boxed(), cb.into_future().boxed()).await {
        Either::Left(..) => "CTRL-C",
        Either::Right(..) => "CTRL-BREAK",
    };

    info!("received {}, exiting", signal_name);

    Ok(())
}
