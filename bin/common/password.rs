//! Common password utilities

use std::{env, io};

use log::debug;

/// Read server's password from environment variable or TTY
pub fn read_server_password(server_name: &str) -> io::Result<String> {
    // specific SS_SERVER_${server_name}_PASSWORD
    let key = format!("SS_SERVER_{}_PASSWORD", server_name);
    if let Ok(pwd) = env::var(&key) {
        debug!("got server {} password from environment variable {}", server_name, key);
        return Ok(pwd);
    }

    // common SS_SERVER_PASSWORD
    if let Ok(pwd) = env::var("SS_SERVER_PASSWORD") {
        debug!(
            "got server {} password from environment variable SS_SERVER_PASSWORD",
            server_name
        );
        return Ok(pwd);
    }

    // read from TTY
    let tty_prompt = format!("({}) Password: ", server_name);
    if let Ok(pwd) = rpassword::read_password_from_tty(Some(&tty_prompt)) {
        debug!("got server {} password from tty prompt", server_name);
        return Ok(pwd);
    }

    Err(io::Error::new(io::ErrorKind::Other, "no server password found"))
}
