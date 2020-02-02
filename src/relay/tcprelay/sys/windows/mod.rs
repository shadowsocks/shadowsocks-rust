use std::{
    io::{self, Error, ErrorKind},
    net::SocketAddr,
};

use tokio::net::{TcpListener, TcpStream};

pub fn check_support_tproxy() -> io::Result<()> {
    // Windows seems can support transparent proxy by Windows Filtering Platform
    // https://docs.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page

    let err = Error::new(ErrorKind::Other, "Windows doesn't support TCP transparent proxy");
    Err(err)
}

pub fn get_original_destination_addr(_: &mut TcpStream) -> io::Result<SocketAddr> {
    unimplemented!("TCP Transparent Proxy (redir) is not supported on this platform");
}

pub async fn create_redir_listener(_: &SocketAddr) -> io::Result<TcpListener> {
    unimplemented!("TCP Transparent Proxy (redir) is not supported on this platform");
}
