use std::io;

use libc;
use tokio_core::reactor::Handle;

use futures::{Future, Stream};

#[cfg(unix)]
pub fn monitor_signal(handle: &Handle) {
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
                      sigterm.for_each(|_| -> Result<(), io::Error> {
                                           panic!("Received SIGTERM, aborting process");
                                       })
                  })
        .map_err(|err| {
                     error!("Failed to monitor SIGTERM, SIGINT, err: {:?}", err);
                 });

    handle.spawn(fut);
}

#[cfg(not(unix))]
pub fn monitor_signal(handle: &Handle) {
    // FIXME: Do nothing ...
}
