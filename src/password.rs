//! Common password utilities

use std::{env, io};

use log::debug;

/// Read server's password from environment variable or TTY
pub fn read_server_password(server_name: &str) -> io::Result<String> {
    // common SS_SERVER_PASSWORD
    if let Ok(pwd) = env::var("SS_SERVER_PASSWORD") {
        debug!(
            "got server {} password from environment variable SS_SERVER_PASSWORD",
            server_name
        );
        return Ok(pwd);
    }

    // read from TTY
    let tty_prompt = format!("({server_name}) Password: ");
    if let Ok(pwd) = rpassword::prompt_password(tty_prompt) {
        debug!("got server {} password from tty prompt", server_name);
        return Ok(pwd);
    }

    Err(io::Error::other("no server password found"))
}
