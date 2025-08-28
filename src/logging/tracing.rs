//! Logging facilities with tracing

use std::io;
use std::io::IsTerminal;

use time::UtcOffset;
use time::format_description::well_known::Rfc3339;
use tracing::level_filters::LevelFilter;
use tracing_appender::rolling::{InitError, RollingFileAppender};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::fmt::time::OffsetTime;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, Registry, fmt};

use crate::config::{
    LogConfig, LogConsoleWriterConfig, LogFileWriterConfig, LogFormatConfig, LogFormatConfigOverride, LogWriterConfig,
};

/// Initialize logger with provided configuration
pub fn init_with_config(bin_name: &str, config: &LogConfig) {
    let layers: Vec<BoxedLayer> = config
        .writers
        .iter()
        .map(|writer| writer.make_layer(bin_name, config))
        .collect();
    tracing_subscriber::registry().with(layers).init();
}

type BoxedLayer = Box<dyn Layer<Registry> + Send + Sync + 'static>;

trait MakeLayer {
    fn make_layer(&self, bin_name: &str, global: &LogConfig) -> BoxedLayer;
}

impl MakeLayer for LogWriterConfig {
    fn make_layer(&self, bin_name: &str, global: &LogConfig) -> BoxedLayer {
        match self {
            LogWriterConfig::Console(console_config) => console_config.make_layer(bin_name, global),
            LogWriterConfig::File(file_config) => file_config.make_layer(bin_name, global),
        }
    }
}

impl MakeLayer for LogConsoleWriterConfig {
    fn make_layer(&self, bin_name: &str, global: &LogConfig) -> BoxedLayer {
        let level = self.level.unwrap_or(global.level);
        let format = apply_override(&global.format, &self.format);
        let ansi = io::stdout().is_terminal();
        make_fmt_layer(bin_name, level, &format, ansi, io::stdout)
    }
}

impl MakeLayer for LogFileWriterConfig {
    fn make_layer(&self, bin_name: &str, global: &LogConfig) -> BoxedLayer {
        let level = self.level.unwrap_or(global.level);
        let format = apply_override(&global.format, &self.format);

        let file_writer = make_file_writer(bin_name, self)
            // don't have the room for a more graceful error handling here
            .expect("Failed to create file writer for logging");
        make_fmt_layer(bin_name, level, &format, false, file_writer)
    }
}

/// Boilerplate for configuring a `fmt::Layer` with `level` and `format` for different writers.
fn make_fmt_layer<W>(bin_name: &str, level: u32, format: &LogFormatConfig, ansi: bool, writer: W) -> BoxedLayer
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let mut layer = fmt::layer().with_level(true);

    // NOTE: ansi is enabled by default.
    // Could be disabled by `NO_COLOR` environment variable.
    // https://no-color.org/
    if !ansi {
        layer = layer.with_ansi(false);
    }

    if level >= 1 {
        layer = layer.with_target(true).with_thread_ids(true).with_thread_names(true);

        if level >= 3 {
            layer = layer.with_file(true).with_line_number(true);
        }
    } else {
        layer = layer.with_target(false).with_thread_ids(false).with_thread_names(false);
    }

    let layer = layer.with_writer(writer);

    let boxed_layer = if format.without_time {
        layer.without_time().boxed()
    } else {
        layer
            .with_timer(OffsetTime::local_rfc_3339()
                // Fallback to UTC. Eagerly evaluate because it is cheap to create.
                .unwrap_or(OffsetTime::new(UtcOffset::UTC, Rfc3339)))
            .boxed()
    };

    let filter = make_env_filter(bin_name, level);
    boxed_layer.with_filter(filter).boxed()
}

fn make_env_filter(bin_name: &str, level: u32) -> EnvFilter {
    match EnvFilter::try_from_default_env() {
        Ok(f) => f,
        Err(_) => match level {
            0 => EnvFilter::builder()
                .with_regex(true)
                .with_default_directive(LevelFilter::ERROR.into())
                .parse_lossy(format!(
                    "warn,{}=info,shadowsocks_rust=info,shadowsocks_service=info,shadowsocks=info",
                    bin_name
                )),
            1 => EnvFilter::builder()
                .with_regex(true)
                .with_default_directive(LevelFilter::ERROR.into())
                .parse_lossy(format!(
                    "warn,{}=debug,shadowsocks_rust=debug,shadowsocks_service=debug,shadowsocks=debug",
                    bin_name
                )),
            2 => EnvFilter::builder()
                .with_regex(true)
                .with_default_directive(LevelFilter::ERROR.into())
                .parse_lossy(format!(
                    "warn,{}=trace,shadowsocks_rust=trace,shadowsocks_service=trace,shadowsocks=trace",
                    bin_name
                )),
            _ => EnvFilter::builder()
                .with_default_directive(LevelFilter::TRACE.into())
                .parse_lossy(""),
        },
    }
}

fn make_file_writer(bin_name: &str, config: &LogFileWriterConfig) -> Result<RollingFileAppender, InitError> {
    // We provide default values here because we don't have access to the
    // `bin_name` elsewhere.
    let prefix = config.prefix.as_deref().unwrap_or(bin_name);
    let suffix = config.suffix.as_deref().unwrap_or("log");

    let mut builder = RollingFileAppender::builder()
        .rotation(config.rotation.into())
        .filename_prefix(prefix)
        .filename_suffix(suffix);

    if let Some(max_files) = config.max_files {
        // setting `max_files` to `0` will cause panicking due to
        // integer underflow in the `tracing_appender` crate.
        if max_files > 0 {
            builder = builder.max_log_files(max_files);
        }
    }

    builder.build(&config.directory)
}

fn apply_override(global: &LogFormatConfig, override_config: &LogFormatConfigOverride) -> LogFormatConfig {
    LogFormatConfig {
        without_time: override_config.without_time.unwrap_or(global.without_time),
    }
}
