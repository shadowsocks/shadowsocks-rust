//! Logging facilities with tracing

use std::io::IsTerminal;

use time::UtcOffset;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt::time::OffsetTime, EnvFilter, FmtSubscriber};

use crate::config::LogConfig;

/// Initialize logger with provided configuration
pub fn init_with_config(bin_name: &str, config: &LogConfig) {
    let debug_level = config.level;
    let without_time = config.format.without_time;

    let mut builder = FmtSubscriber::builder()
        .with_level(true)
        .with_timer(match OffsetTime::local_rfc_3339() {
            Ok(t) => t,
            Err(..) => {
                // Reinit with UTC time
                OffsetTime::new(UtcOffset::UTC, time::format_description::well_known::Rfc3339)
            }
        });

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

    if without_time {
        builder.without_time().init();
    } else {
        builder.init();
    }
}
