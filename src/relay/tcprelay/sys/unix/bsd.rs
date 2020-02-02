use std::{
    io::{self, Error, ErrorKind},
    net::SocketAddr,
};

use tokio::net::{TcpListener, TcpStream};

pub fn check_support_tproxy() -> io::Result<()> {
    let err = Error::new(
        ErrorKind::Other,
        "BSD-like system's TCP transparent proxy is not supported yet",
    );
    Err(err)
}

pub fn get_original_destination_addr(s: &mut TcpStream) -> io::Result<SocketAddr> {
    // ## IPFW
    //
    // For IPFW, uses getsockname() to retrieve destination address
    //
    // FreeBSD: https://www.freebsd.org/doc/handbook/firewalls-ipfw.html
    //
    // ## Packet Filter
    //
    // For modern BSD-like system, uses Packet Filter (pf)
    //
    // https://www.freebsd.org/cgi/man.cgi?query=pf.conf
    // https://www.freebsd.org/doc/handbook/firewalls-pf.html
    //
    // Get original destination from `/dev/pf` with `ioctl(pffd, DIOCNATLOOK, &pnl)`
    //
    // ## Others
    // IP Filter and NPF
    //
    // FIXME: This is far too complicated, and I don't have any machines installed *BSD.
    // macos 10.10+ supposes to have `<net/pfvar.h>` header, but on my laptop with 10.15.2, it doesn't.
    //
    // Ref: (in Chinese) https://github.com/Koriste/koriste.github.io/issues/2

    // This is the oldest IPFW's way
    s.local_addr()
}

pub async fn create_redir_listener(addr: &SocketAddr) -> io::Result<TcpListener> {
    TcpListener::bind(addr).await
}
