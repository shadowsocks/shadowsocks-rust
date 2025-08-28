//! Common configuration utilities

use std::{
    env,
    fs::OpenOptions,
    io::{self, Read},
    path::{Path, PathBuf},
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
#[derive(Deserialize, Debug, Clone, Default)]
#[serde(default)]
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
        json5::from_str(s).map_err(ConfigError::from)
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

        // suppress unused warning
        let _ = matches;
    }
}

/// Logger configuration
#[cfg(feature = "logging")]
#[derive(Deserialize, Debug, Clone)]
#[serde(default)]
pub struct LogConfig {
    /// Default log level for all writers, [0, 3]
    pub level: u32,
    /// Default format configuration for all writers
    pub format: LogFormatConfig,
    /// Log writers configuration
    pub writers: Vec<LogWriterConfig>,
    /// Deprecated: Path to the `log4rs` config file
    pub config_path: Option<PathBuf>,
}

#[cfg(feature = "logging")]
impl Default for LogConfig {
    fn default() -> Self {
        LogConfig {
            level: 0,
            format: LogFormatConfig::default(),
            writers: vec![LogWriterConfig::Console(LogConsoleWriterConfig::default())],
            config_path: None,
        }
    }
}

/// Logger format configuration
#[cfg(feature = "logging")]
#[derive(Deserialize, Debug, Clone, Default, Eq, PartialEq)]
#[serde(default)]
pub struct LogFormatConfig {
    pub without_time: bool,
}

/// Holds writer-specific configuration for logging
#[cfg(feature = "logging")]
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum LogWriterConfig {
    Console(LogConsoleWriterConfig),
    File(LogFileWriterConfig),
}

/// Console appender configuration for logging
#[cfg(feature = "logging")]
#[derive(Deserialize, Debug, Clone, Default)]
pub struct LogConsoleWriterConfig {
    /// Level override
    #[serde(default)]
    pub level: Option<u32>,
    /// Format override
    #[serde(default)]
    pub format: LogFormatConfigOverride,
}

/// Logger format override
#[cfg(feature = "logging")]
#[derive(Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct LogFormatConfigOverride {
    pub without_time: Option<bool>,
}

/// File appender configuration for logging
#[cfg(feature = "logging")]
#[derive(Deserialize, Debug, Clone)]
pub struct LogFileWriterConfig {
    /// Level override
    #[serde(default)]
    pub level: Option<u32>,
    /// Format override
    #[serde(default)]
    pub format: LogFormatConfigOverride,

    /// Directory to store log files
    pub directory: PathBuf,
    /// Rotation strategy for log files. Default is `Rotation::NEVER`.
    #[serde(default)]
    pub rotation: LogRotation,
    /// Prefix for log file names. Default is the binary name.
    #[serde(default)]
    pub prefix: Option<String>,
    /// Suffix for log file names. Default is "log".
    #[serde(default)]
    pub suffix: Option<String>,
    /// Maximum number of log files to keep. Default is `None`, meaning no limit.
    #[serde(default)]
    pub max_files: Option<usize>,
}

/// Log rotation frequency
#[cfg(feature = "logging")]
#[derive(Deserialize, Debug, Copy, Clone, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LogRotation {
    #[default]
    Never,
    Hourly,
    Daily,
}

#[cfg(feature = "logging")]
impl From<LogRotation> for tracing_appender::rolling::Rotation {
    fn from(rotation: LogRotation) -> Self {
        match rotation {
            LogRotation::Never => Self::NEVER,
            LogRotation::Hourly => Self::HOURLY,
            LogRotation::Daily => Self::DAILY,
        }
    }
}

/// Runtime mode (Tokio)
#[derive(Deserialize, Debug, Clone, Copy, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    /// Single-Thread Runtime
    #[cfg_attr(not(feature = "multi-threaded"), default)]
    SingleThread,
    /// Multi-Thread Runtime
    #[cfg(feature = "multi-threaded")]
    #[cfg_attr(feature = "multi-threaded", default)]
    MultiThread,
}

/// Runtime configuration
#[derive(Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct RuntimeConfig {
    /// Multithread runtime worker count, CPU count if not configured
    #[cfg(feature = "multi-threaded")]
    pub worker_count: Option<usize>,
    /// Runtime Mode, single-thread, multi-thread
    pub mode: RuntimeMode,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deser_empty() {
        // empty config should load successfully
        let config: Config = Config::load_from_str("{}").unwrap();
        assert_eq!(config.runtime.mode, RuntimeMode::default());
        #[cfg(feature = "multi-threaded")]
        {
            assert!(config.runtime.worker_count.is_none());
        }
        #[cfg(feature = "logging")]
        {
            assert_eq!(config.log.level, 0);
            assert!(!config.log.format.without_time);
            // default writer configuration should contain a stdout writer
            assert_eq!(config.log.writers.len(), 1);
            if let LogWriterConfig::Console(stdout_config) = &config.log.writers[0] {
                assert_eq!(stdout_config.level, None);
                assert_eq!(stdout_config.format.without_time, None);
            } else {
                panic!("Expected a stdout writer configuration");
            }
        }
    }

    #[test]
    fn test_deser_disable_logging() {
        // allow user explicitly disable logging by providing an empty writers array
        let config_str = r#"
            {
                "log": {
                    "writers": []
                }
            }
        "#;
        let config: Config = Config::load_from_str(config_str).unwrap();
        #[cfg(feature = "logging")]
        {
            assert_eq!(config.log.level, 0);
            assert!(!config.log.format.without_time);
            assert!(config.log.writers.is_empty());
        }
    }

    #[test]
    fn test_deser_file_writer_full() {
        let config_str = r#"
            {
                "log": {
                    "writers": [
                        {
                            "file": {
                                "level": 2,
                                "format": {
                                    "without_time": true
                                },
                                "directory": "/var/log/shadowsocks",
                                "rotation": "daily",
                                "prefix": "ss-rust",
                                "suffix": "log",
                                "max_files": 5
                            }
                        }
                    ]
                }
            }
        "#;
        let config: Config = Config::load_from_str(config_str).unwrap();
        #[cfg(feature = "logging")]
        {
            assert_eq!(config.log.writers.len(), 1);
            if let LogWriterConfig::File(file_config) = &config.log.writers[0] {
                assert_eq!(file_config.level, Some(2));
                assert_eq!(file_config.format.without_time, Some(true));
                assert_eq!(file_config.directory, PathBuf::from("/var/log/shadowsocks"));
                assert_eq!(file_config.rotation, LogRotation::Daily);
                assert_eq!(file_config.prefix.as_deref(), Some("ss-rust"));
                assert_eq!(file_config.suffix.as_deref(), Some("log"));
                assert_eq!(file_config.max_files, Some(5));
            } else {
                panic!("Expected a file writer configuration");
            }
        }
    }

    #[test]
    fn test_deser_file_writer_minimal() {
        // Minimal valid file writer configuration
        let config_str = r#"
            {
                "log": {
                    "writers": [
                        {
                            "file": {
                                "directory": "/var/log/shadowsocks"
                            }
                        }
                    ]
                }
            }
        "#;
        let config: Config = Config::load_from_str(config_str).unwrap();
        #[cfg(feature = "logging")]
        {
            assert_eq!(config.log.writers.len(), 1);
            if let LogWriterConfig::File(file_config) = &config.log.writers[0] {
                assert_eq!(file_config.level, None);
                assert_eq!(file_config.format.without_time, None);
                assert_eq!(file_config.directory, PathBuf::from("/var/log/shadowsocks"));
                assert_eq!(file_config.rotation, LogRotation::Never);
                assert!(file_config.prefix.is_none());
                assert!(file_config.suffix.is_none());
                assert!(file_config.max_files.is_none());
            } else {
                panic!("Expected a file writer configuration");
            }
        }
    }
    #[test]
    fn test_deser_console_writer_full() {
        let config_str = r#"
            {
                "log": {
                    "writers": [
                        {
                            "console": {
                                "level": 1,
                                "format": {
                                    "without_time": false
                                }
                            }
                        }
                    ]
                }
            }
        "#;
        let config: Config = Config::load_from_str(config_str).unwrap();
        #[cfg(feature = "logging")]
        {
            assert_eq!(config.log.writers.len(), 1);
            if let LogWriterConfig::Console(stdout_config) = &config.log.writers[0] {
                assert_eq!(stdout_config.level, Some(1));
                assert_eq!(stdout_config.format.without_time, Some(false));
            } else {
                panic!("Expected a console writer configuration");
            }
        }
    }

    #[test]
    fn test_deser_console_writer_minimal() {
        // Minimal valid console writer configuration
        let config_str = r#"
            {
                "log": {
                    "writers": [
                        {
                            "console": {}
                        }
                    ]
                }
            }
        "#;
        let config: Config = Config::load_from_str(config_str).unwrap();
        #[cfg(feature = "logging")]
        {
            assert_eq!(config.log.writers.len(), 1);
            if let LogWriterConfig::Console(stdout_config) = &config.log.writers[0] {
                assert_eq!(stdout_config.level, None);
                assert_eq!(stdout_config.format.without_time, None);
            } else {
                panic!("Expected a console writer configuration");
            }
        }
    }
}
