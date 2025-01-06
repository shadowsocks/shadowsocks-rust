// /// Exit code when server exits unexpectedly
// pub const EXIT_CODE_SERVER_EXIT_UNEXPECTEDLY: sysexits::ExitCode = sysexits::ExitCode::Software;
// /// Exit code when server aborted
// pub const EXIT_CODE_SERVER_ABORTED: sysexits::ExitCode = sysexits::ExitCode::Software;
// /// Exit code when loading configuration from file fails
// pub const EXIT_CODE_LOAD_CONFIG_FAILURE: sysexits::ExitCode = sysexits::ExitCode::Config;
// /// Exit code when loading ACL from file fails
// pub const EXIT_CODE_LOAD_ACL_FAILURE: sysexits::ExitCode = sysexits::ExitCode::Config;
// /// Exit code when insufficient params are passed via CLI
// pub const EXIT_CODE_INSUFFICIENT_PARAMS: sysexits::ExitCode = sysexits::ExitCode::Usage;

pub type ShadowsocksResult<T = ()> = Result<T, ShadowsocksError>;

#[derive(Clone, Debug)]
pub enum ShadowsocksError {
    ServerExitUnexpectedly(String),
    ServerAborted(String),
    LoadConfigFailure(String),
    LoadAclFailure(String),
    InsufficientParams(String),
}

impl ShadowsocksError {
    pub fn error_code(&self) -> sysexits::ExitCode {
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

impl std::process::Termination for ShadowsocksError {
    #[inline]
    fn report(self) -> std::process::ExitCode {
        self.error_code().report()
    }
}
