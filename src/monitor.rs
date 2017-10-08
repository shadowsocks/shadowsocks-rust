#![allow(unused_imports)]

use std::io;

use libc;
use tokio_core::reactor::Handle;

use futures::{Future, Stream};

use plugin::Plugin;

#[cfg(unix)]
pub fn monitor_signal(handle: &Handle, mut plugins: Vec<Plugin>) {
    use tokio_signal::unix::Signal;

    let fut = Signal::new(libc::SIGCHLD, handle)
        .and_then(|signal| {
            signal.for_each(|_| -> Result<(), io::Error> {
                panic!("Plugin exited unexpectly (SIGCHLD)");
            })
        })
        .map_err(|err| {
            error!("Failed to monitor SIGCHLD, err: {:?}", err);
        });

    handle.spawn(fut);

    let fut = Signal::new(libc::SIGTERM, handle)
        .and_then(|sigterm| {
            sigterm.for_each(move |_| -> Result<(), io::Error> {
                info!("Exiting on SIGTERM");
                plugins.truncate(0);
                ::std::process::exit(0);
            })
        })
        .map_err(|err| {
            error!("Failed to monitor SIGTERM, err: {:?}", err);
        });

    handle.spawn(fut);
}

#[cfg(not(unix))]
pub fn monitor_signal(_handle: &Handle) {
    // FIXME: Do nothing ...
}
