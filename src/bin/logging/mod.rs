use std::env;
use std::io::{self, Write};

use env_logger::{fmt::Formatter, Builder};
use log::{LevelFilter, Record};

pub fn init(without_time: bool, debug_level: u64, bin_name: &str) {
    let mut log_builder = Builder::new();
    log_builder.filter(None, LevelFilter::Info);

    match debug_level {
        0 => {
            // Default filter
            log_builder.format(move |fmt, r| log_time(fmt, without_time, r));
        }
        1 => {
            let log_builder = log_builder.format(move |fmt, r| log_time_module(fmt, without_time, r));
            log_builder.filter(Some(bin_name), LevelFilter::Debug);
        }
        2 => {
            let log_builder = log_builder.format(move |fmt, r| log_time_module(fmt, without_time, r));
            log_builder
                .filter(Some(bin_name), LevelFilter::Debug)
                .filter(Some("shadowsocks"), LevelFilter::Debug);
        }
        3 => {
            let log_builder = log_builder.format(move |fmt, r| log_time_module(fmt, without_time, r));
            log_builder
                .filter(Some(bin_name), LevelFilter::Trace)
                .filter(Some("shadowsocks"), LevelFilter::Trace);
        }
        _ => {
            let log_builder = log_builder.format(move |fmt, r| log_time_module(fmt, without_time, r));
            log_builder.filter(None, LevelFilter::Trace);
        }
    }

    if let Ok(env_conf) = env::var("RUST_LOG") {
        log_builder.parse_filters(&env_conf);
    }

    log_builder.init();
}

fn log_time(fmt: &mut Formatter, without_time: bool, record: &Record) -> io::Result<()> {
    if without_time {
        writeln!(fmt, "[{}] {}", record.level(), record.args())
    } else {
        writeln!(
            fmt,
            "[{}][{}] {}",
            time::now().strftime("%Y-%m-%d][%H:%M:%S.%f").unwrap(),
            record.level(),
            record.args()
        )
    }
}

fn log_time_module(fmt: &mut Formatter, without_time: bool, record: &Record) -> io::Result<()> {
    if without_time {
        writeln!(
            fmt,
            "[{}] [{}] {}",
            record.level(),
            record.module_path().unwrap_or("*"),
            record.args()
        )
    } else {
        writeln!(
            fmt,
            "[{}][{}] [{}] {}",
            time::now().strftime("%Y-%m-%d][%H:%M:%S.%f").unwrap(),
            record.level(),
            record.module_path().unwrap_or("*"),
            record.args()
        )
    }
}
