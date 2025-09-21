pub type Errno = libc::c_int;

/// This error type for `Daemonize` `start` method.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Error {
    kind: ErrorKind,
}

/// This error type for `Daemonize` `start` method.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum ErrorKind {
    Fork(Errno),
    Wait(Errno),
    DetachSession(Errno),
    GroupNotFound,
    GroupContainsNul,
    SetGroup(Errno),
    UserNotFound,
    UserContainsNul,
    SetUser(Errno),
    ChangeDirectory(Errno),
    PathContainsNul,
    OpenPidfile(Errno),
    GetPidfileFlags(Errno),
    SetPidfileFlags(Errno),
    LockPidfile(Errno),
    ChownPidfile(Errno),
    OpenDevnull(Errno),
    RedirectStreams(Errno),
    CloseDevnull(Errno),
    TruncatePidfile(Errno),
    WritePid(Errno),
    WritePidUnspecifiedError,
    Chroot(Errno),
}

impl ErrorKind {
    fn description(&self) -> &str {
        match self {
            ErrorKind::Fork(_) => "unable to fork",
            ErrorKind::Wait(_) => "wait failed",
            ErrorKind::DetachSession(_) => "unable to create new session",
            ErrorKind::GroupNotFound => "unable to resolve group name to group id",
            ErrorKind::GroupContainsNul => "group option contains NUL",
            ErrorKind::SetGroup(_) => "unable to set group",
            ErrorKind::UserNotFound => "unable to resolve user name to user id",
            ErrorKind::UserContainsNul => "user option contains NUL",
            ErrorKind::SetUser(_) => "unable to set user",
            ErrorKind::ChangeDirectory(_) => "unable to change directory",
            ErrorKind::PathContainsNul => "pid_file option contains NUL",
            ErrorKind::OpenPidfile(_) => "unable to open pid file",
            ErrorKind::GetPidfileFlags(_) => "unable get pid file flags",
            ErrorKind::SetPidfileFlags(_) => "unable set pid file flags",
            ErrorKind::LockPidfile(_) => "unable to lock pid file",
            ErrorKind::ChownPidfile(_) => "unable to chown pid file",
            ErrorKind::OpenDevnull(_) => "unable to open /dev/null",
            ErrorKind::RedirectStreams(_) => "unable to redirect standard streams to /dev/null",
            ErrorKind::CloseDevnull(_) => "unable to close /dev/null",
            ErrorKind::TruncatePidfile(_) => "unable to truncate pid file",
            ErrorKind::WritePid(_) => "unable to write self pid to pid file",
            ErrorKind::WritePidUnspecifiedError => "unable to write self pid to pid file due to unknown reason",
            ErrorKind::Chroot(_) => "unable to chroot into directory",
        }
    }

    fn errno(&self) -> Option<Errno> {
        match self {
            ErrorKind::Fork(errno) => Some(*errno),
            ErrorKind::Wait(errno) => Some(*errno),
            ErrorKind::DetachSession(errno) => Some(*errno),
            ErrorKind::GroupNotFound => None,
            ErrorKind::GroupContainsNul => None,
            ErrorKind::SetGroup(errno) => Some(*errno),
            ErrorKind::UserNotFound => None,
            ErrorKind::UserContainsNul => None,
            ErrorKind::SetUser(errno) => Some(*errno),
            ErrorKind::ChangeDirectory(errno) => Some(*errno),
            ErrorKind::PathContainsNul => None,
            ErrorKind::OpenPidfile(errno) => Some(*errno),
            ErrorKind::GetPidfileFlags(errno) => Some(*errno),
            ErrorKind::SetPidfileFlags(errno) => Some(*errno),
            ErrorKind::LockPidfile(errno) => Some(*errno),
            ErrorKind::ChownPidfile(errno) => Some(*errno),
            ErrorKind::OpenDevnull(errno) => Some(*errno),
            ErrorKind::RedirectStreams(errno) => Some(*errno),
            ErrorKind::CloseDevnull(errno) => Some(*errno),
            ErrorKind::TruncatePidfile(errno) => Some(*errno),
            ErrorKind::WritePid(errno) => Some(*errno),
            ErrorKind::WritePidUnspecifiedError => None,
            ErrorKind::Chroot(errno) => Some(*errno),
        }
    }
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.description())?;
        if let Some(errno) = self.errno() {
            write!(f, ", errno {}", errno)?
        }
        Ok(())
    }
}

impl std::error::Error for ErrorKind {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.kind)
    }
}

impl std::error::Error for Error {}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self { kind }
    }
}

pub trait Num {
    fn is_err(&self) -> bool;
}

impl Num for i8 {
    fn is_err(&self) -> bool {
        *self == -1
    }
}

impl Num for i16 {
    fn is_err(&self) -> bool {
        *self == -1
    }
}

impl Num for i32 {
    fn is_err(&self) -> bool {
        *self == -1
    }
}

impl Num for i64 {
    fn is_err(&self) -> bool {
        *self == -1
    }
}

impl Num for isize {
    fn is_err(&self) -> bool {
        *self == -1
    }
}

pub fn check_err<N: Num, F: FnOnce(Errno) -> ErrorKind>(ret: N, f: F) -> Result<N, ErrorKind> {
    if ret.is_err() { Err(f(errno())) } else { Ok(ret) }
}

pub fn errno() -> Errno {
    std::io::Error::last_os_error().raw_os_error().expect("errno")
}
