
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
