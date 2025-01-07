//! Shadowsocks-specific error encoding.

/// A result with a shadowsocks-specific error.
pub type ShadowsocksResult<T = ()> = Result<T, ShadowsocksError>;

/// A generic error class which encodes all possible ways the application can
/// fail, along with debug information.
#[derive(Clone, Debug)]
pub enum ShadowsocksError {
    ServerExitUnexpectedly(String),
    ServerAborted(String),
    LoadConfigFailure(String),
    LoadAclFailure(String),
    InsufficientParams(String),
}

impl ShadowsocksError {
    /// The corresponding `sysexits::ExitCode` for this error.
    pub fn exit_code(&self) -> sysexits::ExitCode {
        match self {
            Self::ServerExitUnexpectedly(_) | Self::ServerAborted(_) => sysexits::ExitCode::Software,
            Self::LoadConfigFailure(_) | Self::LoadAclFailure(_) => sysexits::ExitCode::Config,
            Self::InsufficientParams(_) => sysexits::ExitCode::Usage,
        }
    }
}

impl std::fmt::Display for ShadowsocksError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ServerExitUnexpectedly(msg)
            | Self::ServerAborted(msg)
            | Self::LoadConfigFailure(msg)
            | Self::LoadAclFailure(msg)
            | Self::InsufficientParams(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for ShadowsocksError {}
