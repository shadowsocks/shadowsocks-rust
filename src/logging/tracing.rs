//! Logging facilities with tracing

use std::io::IsTerminal;

use time::format_description::well_known::Rfc3339;
use time::UtcOffset;
use tracing::level_filters::LevelFilter;
use tracing_appender::rolling::{InitError, RollingFileAppender};
use tracing_subscriber::fmt::format::{DefaultFields, Format, Full};
use tracing_subscriber::fmt::time::OffsetTime;
use tracing_subscriber::fmt::{MakeWriter, SubscriberBuilder};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

use crate::config::{LogConfig, LogFileConfig};

/// Initialize logger with provided configuration
pub fn init_with_config(bin_name: &str, config: &LogConfig) {
    let debug_level = config.level;
    let without_time = config.format.without_time;

    let mut builder = FmtSubscriber::builder().with_level(true).with_timer(
        OffsetTime::local_rfc_3339()
                    // Fallback to UTC. Eagerly evaluate because it is cheap to create.
                    .unwrap_or(OffsetTime::new(UtcOffset::UTC, Rfc3339)),
    );

    // NOTE: ansi is enabled by default.
    // Could be disabled by `NO_COLOR` environment variable.
    // https://no-color.org/
    if !std::io::stdout().is_terminal() {
        builder = builder.with_ansi(false);
    }

    if debug_level >= 1 {
        builder = builder.with_target(true).with_thread_ids(true).with_thread_names(true);

        if debug_level >= 3 {
            builder = builder.with_file(true).with_line_number(true);
        }
    } else {
        builder = builder
            .with_target(false)
            .with_thread_ids(false)
            .with_thread_names(false);
    }

    let filter = match EnvFilter::try_from_default_env() {
        Ok(f) => f,
        Err(..) => match debug_level {
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
    };
    let builder = builder.with_env_filter(filter);

    if let Some(ref file_config) = config.file {
        let file_writer = make_file_writer(bin_name, file_config)
            // don't have the room for a more graceful error handling here
            .expect("Failed to create file writer for logging");
        init(builder.with_ansi(false).with_writer(file_writer), without_time);
    } else {
        init(builder, without_time);
    }
}

fn make_file_writer(bin_name: &str, config: &LogFileConfig) -> Result<RollingFileAppender, InitError> {
    let rotation = config.rotation.clone();
    // We provide default values here because we don't have access to the
    // `bin_name` elsewhere.
    let prefix = config.prefix.as_deref().unwrap_or(bin_name);
    let suffix = config.suffix.as_deref().unwrap_or("log");

    let mut builder = RollingFileAppender::builder()
        .rotation(rotation)
        .filename_prefix(prefix)
        .filename_suffix(suffix);

    if let Some(max_files) = config.max_files {
        builder = builder.max_log_files(max_files);
    }

    builder.build(&config.directory)
}

/// Initialize the logger with the provided builder and options.
///
/// This handles the `without_time` option generically for builders that
/// are configured with different `MakeWriter` concrete types.
fn init<W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static>(
    builder: SubscriberBuilder<DefaultFields, Format<Full, OffsetTime<Rfc3339>>, EnvFilter, W>,
    without_time: bool,
) {
    if without_time {
        builder.without_time().init();
    } else {
        builder.init();
    }
}
