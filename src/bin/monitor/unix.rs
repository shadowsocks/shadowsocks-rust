use futures::{Future, Stream};
use libc;
use log::{error, info};
use std::io;
use tokio_signal::unix::Signal;

pub fn create_signal_monitor() -> impl Future<Item = (), Error = io::Error> + Send {
    // Future resolving to two signal streams. Can fail if setting up signal monitoring fails
    let signals_future = Signal::new(libc::SIGTERM).join(Signal::new(libc::SIGINT));

    signals_future
       // The future resolved into our two streams of signals
       .and_then(|(sigterms, sigints)| {
           // Stream of all signals we care about
           let signals = sigterms.select(sigints);
           // Take only the first signal in the stream and log that it was triggered
           signals.take(1).for_each(|signal| {
               let signal_name = match signal {
                   libc::SIGTERM => "SIGTERM",
                   libc::SIGINT => "SIGINT",
                   _ => unreachable!(),
               };
               info!("Received {}, exiting", signal_name);
               Ok(())
           }).map_err(|error| {
               error!("Error while listening on process signals: {:?}", error);
               error
           })
       })
       .map_err(|error| {
           error!("Failed to set up process signal monitoring: {:?}", error);
           error
       })
}
