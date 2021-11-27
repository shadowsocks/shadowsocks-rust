use futures;
use std::io;

/// Create a monitor future for signals
///
/// This is a dummy future in the current platform.
pub async fn create_signal_monitor() -> io::Result<()> {
    // FIXME: What can I do ...
    // Blocks forever
    futures::empty::<(), io::Error>().await
}
