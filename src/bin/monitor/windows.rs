use futures::{self, Future, Stream};
use log::{error, info};
use std::io;
use tokio::net::signal::windows::Event;

pub fn create_signal_monitor() -> impl Future<Item = (), Error = io::Error> + Send {
    // Must be wrapped with a future, because when `Event` is being created, it will spawn
    // a task into the current executor. So if there is no current running executor, thread
    // will panic.
    let events = futures::lazy(|| {
        Event::ctrl_c()
            .join(Event::ctrl_break())
            .and_then(|(c_signals, break_signals)| {
                // Stream of all signals we care about
                let signals = c_signals.select(break_signals);
                // Take only the first signal in the stream and log that it was triggered
                signals
                    .take(1)
                    .for_each(|()| {
                        info!("Received shutdown signal, exiting");
                        Ok(())
                    })
                    .map_err(|error| {
                        error!("Error while listening on process signals: {:?}", error);
                        error
                    })
            })
            .map_err(|error| {
                error!("Failed to set up process signal monitoring: {:?}", error);
                error
            })
    });

    events
}
