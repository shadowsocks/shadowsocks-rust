//! UDP Socket options and extra data

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct UdpSocketControlData {
    /// Session ID in client.
    ///
    /// For identifying an unique association in client
    pub client_session_id: u64,
    /// Session ID in server.
    ///
    /// For identifying an unique association in server
    pub server_session_id: u64,
    /// Packet counter
    pub packet_id: u64,
}
