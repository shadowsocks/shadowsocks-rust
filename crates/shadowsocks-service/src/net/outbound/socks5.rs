//! SOCKS5 negotiation primitives shared by all SOCKS5-aware components.
//!
//! Only the in-band negotiator lives here; the standalone, self-contained
//! [`crate::local::socks::client::socks5::Socks5TcpClient`] /
//! [`crate::local::socks::client::socks5::Socks5UdpClient`] live alongside
//! the local SOCKS server's other clients.

use std::io;

use log::trace;
use shadowsocks::relay::socks5::{
    self, Address, Command, Error as Socks5Error, HandshakeRequest, HandshakeResponse, PasswdAuthRequest,
    PasswdAuthResponse, Reply, TcpRequestHeader, TcpResponseHeader,
};
use tokio::io::{AsyncRead, AsyncWrite};

use super::auth::Socks5Auth;

/// Negotiator for SOCKS5 handshakes on top of an existing byte stream.
///
/// Used both by the proxy chain builder (where multiple hops need to share
/// one underlying byte stream) and as the building block for the
/// standalone SOCKS5 clients.
pub struct Socks5Negotiator;

impl Socks5Negotiator {
    /// Perform the SOCKS5 method negotiation on `stream`, optionally
    /// followed by username/password sub-negotiation.
    pub async fn handshake<S>(stream: &mut S, auth: &Socks5Auth) -> Result<(), Socks5Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let methods = match auth {
            Socks5Auth::None => vec![socks5::SOCKS5_AUTH_METHOD_NONE],
            Socks5Auth::UsernamePassword { .. } => vec![
                socks5::SOCKS5_AUTH_METHOD_PASSWORD,
                socks5::SOCKS5_AUTH_METHOD_NONE,
            ],
        };

        let req = HandshakeRequest::new(methods);
        trace!("socks5 client handshake: {:?}", req);
        req.write_to(stream).await?;

        let resp = HandshakeResponse::read_from(stream).await?;
        trace!("socks5 handshake response: {:?}", resp);

        match resp.chosen_method {
            socks5::SOCKS5_AUTH_METHOD_NONE => Ok(()),
            socks5::SOCKS5_AUTH_METHOD_PASSWORD => match auth {
                Socks5Auth::UsernamePassword { username, password } => {
                    let req = PasswdAuthRequest::new(username.clone(), password.clone());
                    req.write_to(stream).await?;

                    let resp = PasswdAuthResponse::read_from(stream).await?;
                    if resp.status == 0 {
                        Ok(())
                    } else {
                        Err(Socks5Error::IoError(io::Error::other(format!(
                            "SOCKS5 username/password authentication failed with status {:#04x}",
                            resp.status
                        ))))
                    }
                }
                Socks5Auth::None => Err(Socks5Error::IoError(io::Error::other(
                    "SOCKS5 proxy requested USERNAME/PASSWORD but no credentials were provided",
                ))),
            },
            method => Err(Socks5Error::IoError(io::Error::other(format!(
                "SOCKS5 proxy selected unsupported authentication method {method:#04x}"
            )))),
        }
    }

    /// Issue a SOCKS5 command (`TcpConnect` / `UdpAssociate`) on `stream`.
    pub async fn command<S, A>(
        stream: &mut S,
        command: Command,
        addr: A,
    ) -> Result<TcpResponseHeader, Socks5Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
        A: Into<Address>,
    {
        let header = TcpRequestHeader::new(command, addr.into());
        trace!("socks5 {command:?} request: {:?}", header);
        header.write_to(stream).await?;

        let resp = TcpResponseHeader::read_from(stream).await?;
        trace!("socks5 {command:?} response: {:?}", resp);

        match resp.reply {
            Reply::Succeeded => Ok(resp),
            reply => Err(Socks5Error::Reply(reply)),
        }
    }

    /// Convenience: perform handshake + `TcpConnect` on `stream`.
    pub async fn establish_tcp<S, A>(
        stream: &mut S,
        target: A,
        auth: &Socks5Auth,
    ) -> Result<TcpResponseHeader, Socks5Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
        A: Into<Address>,
    {
        Self::handshake(stream, auth).await?;
        Self::command(stream, Command::TcpConnect, addr_helper(target)).await
    }

    /// Convenience: perform handshake + `UdpAssociate` on `stream`.
    /// Returns the TCP response carrying the relay address.
    pub async fn establish_udp_associate<S, A>(
        stream: &mut S,
        announce: A,
        auth: &Socks5Auth,
    ) -> Result<TcpResponseHeader, Socks5Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
        A: Into<Address>,
    {
        Self::handshake(stream, auth).await?;
        Self::command(stream, Command::UdpAssociate, addr_helper(announce)).await
    }
}

#[inline]
fn addr_helper<A: Into<Address>>(a: A) -> Address {
    a.into()
}
