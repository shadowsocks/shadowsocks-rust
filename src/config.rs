//! Common configuration utilities

use std::{
    env,
    fs::OpenOptions,
    io::{self, Read},
    path::{Path, PathBuf},
    str::FromStr,
};

use clap::ArgMatches;
use directories::ProjectDirs;
use serde::Deserialize;

/// Default configuration file path
pub fn get_default_config_path(config_file: &str) -> Option<PathBuf> {
    // config.json in the current working directory ($PWD)
    let config_files = vec![config_file, "config.json"];
    if let Ok(mut path) = env::current_dir() {
        for filename in &config_files {
            path.push(filename);
            if path.exists() {
                return Some(path);
            }
            path.pop();
        }
    } else {
        // config.json in the current working directory (relative path)
        for filename in &config_files {
            let relative_path = PathBuf::from(filename);
            if relative_path.exists() {
                return Some(relative_path);
            }
        }
    }

    // System standard directories
    if let Some(project_dirs) = ProjectDirs::from("org", "shadowsocks", "shadowsocks-rust") {
        // Linux: $XDG_CONFIG_HOME/shadowsocks-rust/config.json
        //        $HOME/.config/shadowsocks-rust/config.json
        // macOS: $HOME/Library/Application Support/org.shadowsocks.shadowsocks-rust/config.json
        // Windows: {FOLDERID_RoamingAppData}/shadowsocks/shadowsocks-rust/config/config.json

        let mut config_path = project_dirs.config_dir().to_path_buf();
        for filename in &config_files {
            config_path.push(filename);
            if config_path.exists() {
                return Some(config_path);
            }
            config_path.pop();
        }
    }

    // UNIX systems, XDG Base Directory
    // https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html
    #[cfg(unix)]
    {
        let base_directories = xdg::BaseDirectories::with_prefix("shadowsocks-rust");
        // $XDG_CONFIG_HOME/shadowsocks-rust/config.json
        // for dir in $XDG_CONFIG_DIRS; $dir/shadowsocks-rust/config.json
        for filename in &config_files {
            if let Some(config_path) = base_directories.find_config_file(filename) {
                return Some(config_path);
            }
        }
    }

    // UNIX global configuration file
    #[cfg(unix)]
    {
        let mut global_config_path = PathBuf::from("/etc/shadowsocks-rust");
        for filename in &config_files {
            global_config_path.push(filename);
            if global_config_path.exists() {
                return Some(global_config_path.to_path_buf());
            }
            global_config_path.pop();
        }
    }

    None
}

/// Error while reading `Config`
#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
    /// Input/Output error
    #[error("{0}")]
    IoError(#[from] io::Error),
    /// JSON parsing error
    #[error("{0}")]
    JsonError(#[from] json5::Error),
    /// Invalid value
    #[error("Invalid value: {0}")]
    InvalidValue(String),
}

/// Configuration Options for shadowsocks service runnables
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// Logger configuration
    #[cfg(feature = "logging")]
    pub log: LogConfig,

    /// Runtime configuration
    pub runtime: RuntimeConfig,
}

impl Config {
    /// Load `Config` from file
    pub fn load_from_file<P: AsRef<Path>>(filename: &P) -> Result<Self, ConfigError> {
        let filename = filename.as_ref();

        let mut reader = OpenOptions::new().read(true).open(filename)?;
        let mut content = String::new();
        reader.read_to_string(&mut content)?;

        Self::load_from_str(&content)
    }

    /// Load `Config` from string
    pub fn load_from_str(s: &str) -> Result<Self, ConfigError> {
        let ssconfig = json5::from_str(s)?;
        Self::load_from_ssconfig(ssconfig)
    }

    fn load_from_ssconfig(ssconfig: SSConfig) -> Result<Self, ConfigError> {
        let mut config = Self::default();

        #[cfg(feature = "logging")]
        if let Some(log) = ssconfig.log {
            let mut nlog = LogConfig::default();
            if let Some(level) = log.level {
                nlog.level = level;
            }

            if let Some(format) = log.format {
                let mut nformat = LogFormatConfig::default();
                if let Some(without_time) = format.without_time {
                    nformat.without_time = without_time;
                }
                nlog.format = nformat;
            }

            if let Some(config_path) = log.config_path {
                nlog.config_path = Some(PathBuf::from(config_path));
            }

            config.log = nlog;
        }

        if let Some(runtime) = ssconfig.runtime {
            let mut nruntime = RuntimeConfig::default();

            #[cfg(feature = "multi-threaded")]
            if let Some(worker_count) = runtime.worker_count {
                nruntime.worker_count = Some(worker_count);
            }

            if let Some(mode) = runtime.mode {
                match mode.parse::<RuntimeMode>() {
                    Ok(m) => nruntime.mode = m,
                    Err(..) => return Err(ConfigError::InvalidValue(mode)),
                }
            }

            config.runtime = nruntime;
        }

        Ok(config)
    }

    /// Set by command line options
    pub fn set_options(&mut self, matches: &ArgMatches) {
        #[cfg(feature = "logging")]
        {
            let debug_level = matches.get_count("VERBOSE");
            if debug_level > 0 {
                self.log.level = debug_level as u32;
            }

            if matches.get_flag("LOG_WITHOUT_TIME") {
                self.log.format.without_time = true;
            }

            if let Some(log_config) = matches.get_one::<PathBuf>("LOG_CONFIG").cloned() {
                self.log.config_path = Some(log_config);
            }
        }

        #[cfg(feature = "multi-threaded")]
        if matches.get_flag("SINGLE_THREADED") {
            self.runtime.mode = RuntimeMode::SingleThread;
        }

        #[cfg(feature = "multi-threaded")]
        if let Some(worker_count) = matches.get_one::<usize>("WORKER_THREADS") {
            self.runtime.worker_count = Some(*worker_count);
        }

        let _ = matches;
    }
}

/// Logger configuration
#[cfg(feature = "logging")]
#[derive(Debug, Clone, Default)]
pub struct LogConfig {
    /// Default logger log level, [0, 3]
    pub level: u32,
    /// Default logger format configuration
    pub format: LogFormatConfig,
    /// Logging configuration file path
    pub config_path: Option<PathBuf>,
}

/// Logger format configuration
#[cfg(feature = "logging")]
#[derive(Debug, Clone, Default)]
pub struct LogFormatConfig {
    pub without_time: bool,
}

/// Runtime mode (Tokio)
#[derive(Debug, Clone, Copy, Default)]
pub enum RuntimeMode {
    /// Single-Thread Runtime
    #[cfg_attr(not(feature = "multi-threaded"), default)]
    SingleThread,
    /// Multi-Thread Runtime
    #[cfg(feature = "multi-threaded")]
    #[cfg_attr(feature = "multi-threaded", default)]
    MultiThread,
}

/// Parse `RuntimeMode` from string error
#[derive(Debug)]
pub struct RuntimeModeError;

impl FromStr for RuntimeMode {
    type Err = RuntimeModeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "single_thread" => Ok(Self::SingleThread),
            #[cfg(feature = "multi-threaded")]
            "multi_thread" => Ok(Self::MultiThread),
            _ => Err(RuntimeModeError),
        }
    }
}

/// Runtime configuration
#[derive(Debug, Clone, Default)]
pub struct RuntimeConfig {
    /// Multithread runtime worker count, CPU count if not configured
    #[cfg(feature = "multi-threaded")]
    pub worker_count: Option<usize>,
    /// Runtime Mode, single-thread, multi-thread
    pub mode: RuntimeMode,
}

#[derive(Deserialize)]
struct SSConfig {
    #[cfg(feature = "logging")]
    log: Option<SSLogConfig>,
    runtime: Option<SSRuntimeConfig>,
}

#[cfg(feature = "logging")]
#[derive(Deserialize)]
struct SSLogConfig {
    level: Option<u32>,
    format: Option<SSLogFormat>,
    config_path: Option<String>,
}

#[cfg(feature = "logging")]
#[derive(Deserialize)]
struct SSLogFormat {
    without_time: Option<bool>,
}

#[derive(Deserialize)]
struct SSRuntimeConfig {
    #[cfg(feature = "multi-threaded")]
    worker_count: Option<usize>,
    mode: Option<String>,
}
