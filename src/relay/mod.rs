pub use self::tcprelay::local::TcpRelayLocal;
pub use self::tcprelay::server::TcpRelayServer;

pub mod tcprelay;

pub trait Relay {
    fn run(&self);
}

pub const SOCK5_VERSION : u8 = 0x05;

pub const SOCK5_AUTH_METHOD_NONE : u8 = 0x00;
pub const SOCK5_AUTH_METHOD_GSSAPI : u8 = 0x01;
pub const SOCK5_AUTH_METHOD_PASSWORD : u8 = 0x02;
pub const SOCK5_AUTH_METHOD_NOT_ACCEPTABLE : u8 = 0xff;

pub const SOCK5_CMD_TCP_CONNECT   : u8 = 0x01;
pub const SOCK5_CMD_TCP_BIND      : u8 = 0x02;
pub const SOCK5_CMD_UDP_ASSOCIATE : u8 = 0x03;

pub const SOCK5_ADDR_TYPE_IPV4        : u8 = 0x01;
pub const SOCK5_ADDR_TYPE_DOMAIN_NAME : u8 = 0x03;
pub const SOCK5_ADDR_TYPE_IPV6        : u8 = 0x04;

pub const SOCK5_REPLY_SUCCEEDED : u8 = 0x00;
pub const SOCK5_REPLY_GENERAL_FAILURE : u8 = 0x01;
pub const SOCK5_REPLY_CONNECTION_NOT_ALLOWED: u8 = 0x02;
pub const SOCK5_REPLY_NETWORK_UNREACHABLE : u8 = 0x03;
pub const SOCK5_REPLY_HOST_UNREACHABLE : u8 = 0x04;
pub const SOCK5_REPLY_CONNECTION_REFUSED : u8 = 0x05;
pub const SOCK5_REPLY_TTL_EXPIRED : u8 = 0x06;
pub const SOCK5_REPLY_COMMAND_NOT_SUPPORTED : u8 = 0x07;
pub const SOCK5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED : u8 = 0x08;

pub enum Sock5AddrType {
    Sock5AddrTypeIpv4,
    Sock5AddrTypeIpv6,
    Sock5AddrTypeDomainName,
}

