#![allow(unused_imports)]

use std::io;
use std::process;

use libc;
use tokio_core::reactor::Handle;

use futures::{self, Future, Stream};

use plugin::Plugin;

#[cfg(unix)]
pub fn monitor_signal(handle: &Handle, plugins: Vec<Plugin>) {
    use tokio_signal::unix::Signal;

    // Monitor SIGCHLD, triggered if subprocess (plugin) is exited.
    let fut1 = Signal::new(libc::SIGCHLD, handle).and_then(|signal| {
        signal.take(1)
              .for_each(|_| -> Result<(), io::Error> {
                            error!("Plugin exited unexpectly (SIGCHLD)");
                            Ok(())
                        })
              .map(|_| libc::SIGCHLD)
    })
                                                 .map_err(|err| {
                                                              error!("Failed to monitor SIGCHLD, err: {:?}", err);
                                                          });

    // Monitor SIGTERM, triggered if shadowsocks is exited gracefully. (Kill by user).
    let fut2 = Signal::new(libc::SIGTERM, handle).and_then(|sigterm| {
                                                               sigterm.take(1)
                                                                      .for_each(|_| -> Result<(), io::Error> {
                                                                                    info!("Received SIGTERM, exiting.");
                                                                                    Ok(())
                                                                                })
                                                                      .map(|_| libc::SIGTERM)
                                                           })
                                                 .map_err(|err| {
                                                              error!("Failed to monitor SIGTERM, err: {:?}", err);
                                                          });

    // Monitor SIGINT, triggered by CTRL-C
    let fut3 = Signal::new(libc::SIGINT, handle).and_then(|sigint| {
                                                              sigint.take(1)
                                                                    .for_each(|_| -> Result<(), io::Error> {
                                                                                  info!("Received SIGINT, exiting.");
                                                                                  Ok(())
                                                                              })
                                                                    .map(|_| libc::SIGINT)
                                                          })
                                                .map_err(|err| {
                                                             error!("Failed to monitor SIGINT, err: {:?}", err);
                                                         });

    // Join them all, if any of them is triggered, kill all subprocesses and exit.
    let fut = fut1.select(fut2)
                  .map(|(sig, _)| sig)
                  .map_err(|(e, _)| e)
                  .select(fut3)
                  .map(|(sig, _)| sig)
                  .map_err(|(e, _)| e)
                  .then(|r| {
        // Something happened ... killing all subprocesses
        info!("Killing {} plugin(s) and then ... Bye Bye :)", plugins.len());
        drop(plugins);

        match r {
            Ok(_signo) => {
                process::exit(0);
            }
            Err(..) => Err(()),
        }
    });

    handle.spawn(fut);
}

#[cfg(windows)]
pub fn monitor_signal(handle: &Handle, plugins: Vec<Plugin>) {
    // FIXME: How to handle SIGTERM equavalent in Windows?

    use tokio_signal::windows::Event;

    let fut1 = Event::ctrl_c(handle).and_then(|ev| {
                                                  ev.take(1).for_each(|_| -> Result<(), io::Error> {
                                                                          error!("Received Ctrl-C event");
                                                                          Ok(())
                                                                      })
                                              })
                                    .map_err(|err| {
                                                 error!("Failed to monitor Ctrl-C event: {:?}", err);
                                             });

    let fut2 = Event::ctrl_break(handle).and_then(|ev| {
                                                      ev.take(1).for_each(|_| -> Result<(), io::Error> {
                                                                              error!("Received Ctrl-Break event");
                                                                              Ok(())
                                                                          })
                                                  })
                                        .map_err(|err| {
                                                     error!("Failed to monitor Ctrl-Break event: {:?}", err);
                                                 });

    let fut = fut1.select(fut2).then(|_| -> Result<(), ()> {
                                         // Something happened ... killing all subprocesses
                                         info!("Killing {} plugin(s) and then ... Bye Bye :)", plugins.len());
                                         drop(plugins);
                                         process::exit(libc::EXIT_FAILURE);
                                     });
    handle.spawn(fut);
}

#[cfg(not(any(windows, unix)))]
pub fn monitor_signal(handle: &Handle, plugins: Vec<Plugin>) {
    // FIXME: What can I do ...
    // Blocks forever
    let fut = futures::empty::<(), ()>().and_then(|_| {
                                                      drop(plugins);
                                                  });
    handle.spawn(fut);
}
