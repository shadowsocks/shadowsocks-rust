
pub trait Relay {
    fn run(&mut self);
}

pub enum Stage {
    StageInit,
    StageHello,
    StageUdpAssoc,
    StageDns,
    StageReply,
    StageStream,
}

pub const SOCK5_VERSION : u8 = 5;

pub const SOCK5_CMD_TCP_CONNECT   : u8 = 1;
pub const SOCK5_CMD_TCP_BIND      : u8 = 2;
pub const SOCK5_CMD_UDP_ASSOCIATE : u8 = 3;

pub const SOCK5_ADDR_MODE_IPV4        : u8 = 0x01;
pub const SOCK5_ADDR_MODE_DOMAIN_NAME : u8 = 0x03;
pub const SOCK5_ADDR_MODE_IPV6        : u8 = 0x04;
