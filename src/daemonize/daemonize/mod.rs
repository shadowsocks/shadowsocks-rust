// Copyright (c) 2016 Fedor Gogolev <knsd@knsd.net>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//!
//! daemonize is a library for writing system daemons. Inspired by the Python library [thesharp/daemonize](https://github.com/thesharp/daemonize).
//!
//! The respository is located at <https://github.com/knsd/daemonize/>.
//!
//! Usage example:
//!
//! ```
//! use std::fs::File;
//!
//! use Daemonize;
//!
//! fn main() {
//!     let stdout = File::create("/tmp/daemon.out").unwrap();
//!     let stderr = File::create("/tmp/daemon.err").unwrap();
//!
//!     let daemonize = Daemonize::new()
//!         .pid_file("/tmp/test.pid") // Every method except `new` and `start`
//!         .chown_pid_file(true)      // is optional, see `Daemonize` documentation
//!         .working_directory("/tmp") // for default behaviour.
//!         .user("nobody")
//!         .group("daemon") // Group name
//!         .group(2)        // or group id.
//!         .umask(0o777)    // Set umask, `0o027` by default.
//!         .stdout(stdout)  // Redirect stdout to `/tmp/daemon.out`.
//!         .stderr(stderr)  // Redirect stderr to `/tmp/daemon.err`.
//!         .privileged_action(|| "Executed before drop privileges");
//!
//!     match daemonize.start() {
//!         Ok(_) => println!("Success, daemonized"),
//!         Err(e) => eprintln!("Error, {}", e),
//!     }
//! }
//! ```

mod error;

use std::env::set_current_dir;
use std::ffi::CString;
use std::fmt;
use std::fs::File;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::exit;

use self::error::{ErrorKind, check_err, errno};

pub use self::error::Error;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
enum UserImpl {
    Name(String),
    Id(libc::uid_t),
}

/// Expects system user id or name. If name is provided it will be resolved to id later.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct User {
    inner: UserImpl,
}

impl From<&str> for User {
    fn from(t: &str) -> User {
        User {
            inner: UserImpl::Name(t.to_owned()),
        }
    }
}

impl From<u32> for User {
    fn from(t: u32) -> User {
        User {
            inner: UserImpl::Id(t as libc::uid_t),
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
enum GroupImpl {
    Name(String),
    Id(libc::gid_t),
}

/// Expects system group id or name. If name is provided it will be resolved to id later.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Group {
    inner: GroupImpl,
}

impl From<&str> for Group {
    fn from(t: &str) -> Group {
        Group {
            inner: GroupImpl::Name(t.to_owned()),
        }
    }
}

impl From<u32> for Group {
    fn from(t: u32) -> Group {
        Group {
            inner: GroupImpl::Id(t as libc::gid_t),
        }
    }
}

/// File mode creation mask.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Mask {
    inner: libc::mode_t,
}

impl From<u32> for Mask {
    fn from(inner: u32) -> Mask {
        Mask {
            inner: inner as libc::mode_t,
        }
    }
}

#[derive(Debug)]
enum StdioImpl {
    Devnull,
    RedirectToFile(File),
    Keep,
}

/// Describes what to do with a standard I/O stream for a child process.
#[derive(Debug)]
pub struct Stdio {
    inner: StdioImpl,
}

impl Stdio {
    pub fn devnull() -> Self {
        Self {
            inner: StdioImpl::Devnull,
        }
    }

    pub fn keep() -> Self {
        Self { inner: StdioImpl::Keep }
    }
}

impl From<File> for Stdio {
    fn from(file: File) -> Self {
        Self {
            inner: StdioImpl::RedirectToFile(file),
        }
    }
}

/// Parent process execution outcome.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub struct Parent {
    pub first_child_exit_code: i32,
}

/// Child process execution outcome.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub struct Child<T> {
    pub privileged_action_result: T,
}

/// Daemonization process outcome. Can be matched to check is it a parent process or a child
/// process.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Outcome<T> {
    Parent(Result<Parent, Error>),
    Child(Result<Child<T>, Error>),
}

impl<T> Outcome<T> {
    pub fn is_parent(&self) -> bool {
        match self {
            Outcome::Parent(_) => true,
            Outcome::Child(_) => false,
        }
    }

    pub fn is_child(&self) -> bool {
        match self {
            Outcome::Parent(_) => false,
            Outcome::Child(_) => true,
        }
    }
}

/// Daemonization options.
///
/// Fork the process in the background, disassociate from its process group and the control terminal.
/// Change umask value to `0o027`, redirect all standard streams to `/dev/null`. Change working
/// directory to `/` or provided value.
///
/// Optionally:
///
///   * maintain and lock the pid-file;
///   * drop user privileges;
///   * drop group privileges;
///   * change root directory;
///   * change the pid-file ownership to provided user (and/or) group;
///   * execute any provided action just before dropping privileges.
///
pub struct Daemonize<T> {
    directory: PathBuf,
    pid_file: Option<PathBuf>,
    chown_pid_file: bool,
    user: Option<User>,
    group: Option<Group>,
    umask: Mask,
    root: Option<PathBuf>,
    privileged_action: Box<dyn FnOnce() -> T>,
    stdin: Stdio,
    stdout: Stdio,
    stderr: Stdio,
}

impl<T> fmt::Debug for Daemonize<T> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("Daemonize")
            .field("directory", &self.directory)
            .field("pid_file", &self.pid_file)
            .field("chown_pid_file", &self.chown_pid_file)
            .field("user", &self.user)
            .field("group", &self.group)
            .field("umask", &self.umask)
            .field("root", &self.root)
            .field("stdin", &self.stdin)
            .field("stdout", &self.stdout)
            .field("stderr", &self.stderr)
            .finish()
    }
}

impl Default for Daemonize<()> {
    fn default() -> Self {
        Self::new()
    }
}

impl Daemonize<()> {
    pub fn new() -> Self {
        Daemonize {
            directory: Path::new("/").to_owned(),
            pid_file: None,
            chown_pid_file: false,
            user: None,
            group: None,
            umask: 0o027.into(),
            privileged_action: Box::new(|| ()),
            root: None,
            stdin: Stdio::devnull(),
            stdout: Stdio::devnull(),
            stderr: Stdio::devnull(),
        }
    }
}

impl<T> Daemonize<T> {
    /// Create pid-file at `path`, lock it exclusive and write daemon pid.
    pub fn pid_file<F: AsRef<Path>>(mut self, path: F) -> Self {
        self.pid_file = Some(path.as_ref().to_owned());
        self
    }

    /// If `chown` is true, daemonize will change the pid-file ownership, if user or group are provided
    pub fn chown_pid_file(mut self, chown: bool) -> Self {
        self.chown_pid_file = chown;
        self
    }

    /// Change working directory to `path` or `/` by default.
    pub fn working_directory<F: AsRef<Path>>(mut self, path: F) -> Self {
        self.directory = path.as_ref().to_owned();
        self
    }

    /// Drop privileges to `user`.
    pub fn user<U: Into<User>>(mut self, user: U) -> Self {
        self.user = Some(user.into());
        self
    }

    /// Drop privileges to `group`.
    pub fn group<G: Into<Group>>(mut self, group: G) -> Self {
        self.group = Some(group.into());
        self
    }

    /// Change umask to `mask` or `0o027` by default.
    pub fn umask<M: Into<Mask>>(mut self, mask: M) -> Self {
        self.umask = mask.into();
        self
    }

    /// Change root to `path`
    pub fn chroot<F: AsRef<Path>>(mut self, path: F) -> Self {
        self.root = Some(path.as_ref().to_owned());
        self
    }

    /// Execute `action` just before dropping privileges. Most common use case is to open
    /// listening socket. Result of `action` execution will be returned by `start` method.
    pub fn privileged_action<N, F: FnOnce() -> N + 'static>(self, action: F) -> Daemonize<N> {
        Daemonize {
            directory: self.directory,
            pid_file: self.pid_file,
            chown_pid_file: self.chown_pid_file,
            user: self.user,
            group: self.group,
            umask: self.umask,
            root: self.root,
            privileged_action: Box::new(action),
            stdin: self.stdin,
            stdout: self.stdout,
            stderr: self.stderr,
        }
    }

    /// Configuration for the child process's standard output stream.
    pub fn stdout<S: Into<Stdio>>(mut self, stdio: S) -> Self {
        self.stdout = stdio.into();
        self
    }

    /// Configuration for the child process's standard error stream.
    pub fn stderr<S: Into<Stdio>>(mut self, stdio: S) -> Self {
        self.stderr = stdio.into();
        self
    }
    /// Start daemonization process, terminate parent after first fork, returns privileged action
    /// result to the child.
    pub fn start(self) -> Result<T, Error> {
        match self.execute() {
            Outcome::Parent(Ok(Parent { first_child_exit_code })) => exit(first_child_exit_code),
            Outcome::Parent(Err(err)) => Err(err),
            Outcome::Child(Ok(child)) => Ok(child.privileged_action_result),
            Outcome::Child(Err(err)) => Err(err),
        }
    }

    /// Execute daemonization process, don't terminate parent after first fork.
    pub fn execute(self) -> Outcome<T> {
        unsafe {
            match perform_fork() {
                Ok(Some(first_child_pid)) => Outcome::Parent(match waitpid(first_child_pid) {
                    Err(err) => Err(err.into()),
                    // return value of `waitpid` may not be i32 on all platforms.
                    #[allow(clippy::unnecessary_cast)]
                    Ok(first_child_exit_code) => Ok(Parent {
                        first_child_exit_code: first_child_exit_code as i32,
                    }),
                }),
                Err(err) => Outcome::Parent(Err(err.into())),
                Ok(None) => match self.execute_child() {
                    Ok(privileged_action_result) => Outcome::Child(Ok(Child {
                        privileged_action_result,
                    })),
                    Err(err) => Outcome::Child(Err(err.into())),
                },
            }
        }
    }

    fn execute_child(self) -> Result<T, ErrorKind> {
        unsafe {
            set_current_dir(&self.directory).map_err(|_| ErrorKind::ChangeDirectory(errno()))?;
            set_sid()?;
            libc::umask(self.umask.inner);

            let pid_file_fd = self
                .pid_file
                .clone()
                .map(|pid_file| create_pid_file(pid_file))
                .transpose()?;

            if perform_fork()?.is_some() {
                exit(0)
            };

            redirect_standard_streams(self.stdin, self.stdout, self.stderr)?;

            let uid = self.user.map(|user| get_user(user)).transpose()?;
            let gid = self.group.map(|group| get_group(group)).transpose()?;

            if self.chown_pid_file {
                let args: Option<(PathBuf, libc::uid_t, libc::gid_t)> = match (self.pid_file, uid, gid) {
                    (Some(pid), Some(uid), Some(gid)) => Some((pid, uid, gid)),
                    (Some(pid), None, Some(gid)) => Some((pid, libc::getuid(), gid)),
                    (Some(pid), Some(uid), None) => Some((pid, uid, libc::getgid())),
                    // Or pid file is not provided, or both user and group
                    _ => None,
                };

                if let Some((pid, uid, gid)) = args {
                    chown_pid_file(pid, uid, gid)?;
                }
            }

            if let Some(pid_file_fd) = pid_file_fd {
                set_cloexec_pid_file(pid_file_fd)?;
            }

            let privileged_action_result = (self.privileged_action)();

            if let Some(root) = self.root {
                change_root(root)?;
            }

            if let Some(gid) = gid {
                set_group(gid)?;
            }

            if let Some(uid) = uid {
                set_user(uid)?;
            }

            if let Some(pid_file_fd) = pid_file_fd {
                write_pid_file(pid_file_fd)?;
            }

            Ok(privileged_action_result)
        }
    }
}

unsafe fn perform_fork() -> Result<Option<libc::pid_t>, ErrorKind> {
    let pid = check_err(libc::fork(), ErrorKind::Fork)?;
    if pid == 0 { Ok(None) } else { Ok(Some(pid)) }
}

unsafe fn waitpid(pid: libc::pid_t) -> Result<libc::c_int, ErrorKind> {
    let mut child_stat = 0;
    check_err(libc::waitpid(pid, &mut child_stat, 0), ErrorKind::Wait)?;
    Ok(libc::WEXITSTATUS(child_stat))
}

unsafe fn set_sid() -> Result<(), ErrorKind> {
    check_err(libc::setsid(), ErrorKind::DetachSession)?;
    Ok(())
}

unsafe fn redirect_standard_streams(stdin: Stdio, stdout: Stdio, stderr: Stdio) -> Result<(), ErrorKind> {
    let devnull_fd = check_err(
        libc::open(b"/dev/null\0" as *const [u8; 10] as _, libc::O_RDWR),
        ErrorKind::OpenDevnull,
    )?;

    let process_stdio = |fd, stdio: Stdio| {
        match stdio.inner {
            StdioImpl::Devnull => {
                check_err(libc::dup2(devnull_fd, fd), ErrorKind::RedirectStreams)?;
            }
            StdioImpl::RedirectToFile(file) => {
                let raw_fd = file.as_raw_fd();
                check_err(libc::dup2(raw_fd, fd), ErrorKind::RedirectStreams)?;
            }
            StdioImpl::Keep => (),
        };
        Ok(())
    };

    process_stdio(libc::STDIN_FILENO, stdin)?;
    process_stdio(libc::STDOUT_FILENO, stdout)?;
    process_stdio(libc::STDERR_FILENO, stderr)?;

    check_err(libc::close(devnull_fd), ErrorKind::CloseDevnull)?;

    Ok(())
}

unsafe fn get_group(group: Group) -> Result<libc::gid_t, ErrorKind> {
    match group.inner {
        GroupImpl::Id(id) => Ok(id),
        GroupImpl::Name(name) => {
            let s = CString::new(name).map_err(|_| ErrorKind::GroupContainsNul)?;
            match get_gid_by_name(&s) {
                Some(id) => get_group(id.into()),
                None => Err(ErrorKind::GroupNotFound),
            }
        }
    }
}

unsafe fn set_group(group: libc::gid_t) -> Result<(), ErrorKind> {
    check_err(libc::setregid(group, group), ErrorKind::SetGroup)?;
    Ok(())
}

unsafe fn get_user(user: User) -> Result<libc::uid_t, ErrorKind> {
    match user.inner {
        UserImpl::Id(id) => Ok(id),
        UserImpl::Name(name) => {
            let s = CString::new(name).map_err(|_| ErrorKind::UserContainsNul)?;
            match get_uid_by_name(&s) {
                Some(id) => get_user(id.into()),
                None => Err(ErrorKind::UserNotFound),
            }
        }
    }
}

unsafe fn set_user(user: libc::uid_t) -> Result<(), ErrorKind> {
    check_err(libc::setreuid(user, user), ErrorKind::SetUser)?;
    Ok(())
}

unsafe fn create_pid_file(path: PathBuf) -> Result<libc::c_int, ErrorKind> {
    let path_c = pathbuf_into_cstring(path)?;

    let fd = check_err(
        libc::open(path_c.as_ptr(), libc::O_WRONLY | libc::O_CREAT, 0o666),
        ErrorKind::OpenPidfile,
    )?;

    check_err(libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB), ErrorKind::LockPidfile)?;
    Ok(fd)
}

unsafe fn chown_pid_file(path: PathBuf, uid: libc::uid_t, gid: libc::gid_t) -> Result<(), ErrorKind> {
    let path_c = pathbuf_into_cstring(path)?;
    check_err(libc::chown(path_c.as_ptr(), uid, gid), ErrorKind::ChownPidfile)?;
    Ok(())
}

unsafe fn write_pid_file(fd: libc::c_int) -> Result<(), ErrorKind> {
    let pid = libc::getpid();
    let pid_buf = format!("{}\n", pid).into_bytes();
    let pid_length = pid_buf.len();
    let pid_c = CString::new(pid_buf).unwrap();
    check_err(libc::ftruncate(fd, 0), ErrorKind::TruncatePidfile)?;

    let written = check_err(
        libc::write(fd, pid_c.as_ptr() as *const libc::c_void, pid_length),
        ErrorKind::WritePid,
    )?;

    if written < pid_length as isize {
        return Err(ErrorKind::WritePidUnspecifiedError);
    }

    Ok(())
}

unsafe fn set_cloexec_pid_file(fd: libc::c_int) -> Result<(), ErrorKind> {
    if cfg!(not(target_os = "redox")) {
        let flags = check_err(libc::fcntl(fd, libc::F_GETFD), ErrorKind::GetPidfileFlags)?;

        check_err(
            libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC),
            ErrorKind::SetPidfileFlags,
        )?;
    } else {
        check_err(libc::ioctl(fd, libc::FIOCLEX), ErrorKind::SetPidfileFlags)?;
    }
    Ok(())
}

unsafe fn change_root(path: PathBuf) -> Result<(), ErrorKind> {
    let path_c = pathbuf_into_cstring(path)?;
    check_err(libc::chroot(path_c.as_ptr()), ErrorKind::Chroot)?;
    Ok(())
}

unsafe fn get_gid_by_name(name: &CString) -> Option<libc::gid_t> {
    let ptr = libc::getgrnam(name.as_ptr() as *const libc::c_char);
    if ptr.is_null() {
        None
    } else {
        let s = &*ptr;
        Some(s.gr_gid)
    }
}

unsafe fn get_uid_by_name(name: &CString) -> Option<libc::uid_t> {
    let ptr = libc::getpwnam(name.as_ptr() as *const libc::c_char);
    if ptr.is_null() {
        None
    } else {
        let s = &*ptr;
        Some(s.pw_uid)
    }
}

fn pathbuf_into_cstring(path: PathBuf) -> Result<CString, ErrorKind> {
    CString::new(path.into_os_string().into_vec()).map_err(|_| ErrorKind::PathContainsNul)
}
