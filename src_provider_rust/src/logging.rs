// Logging utilities
// Corresponds to akv_logging.c

use std::io::Write;
use std::sync::Once;

static INIT: Once = Once::new();

/// Initialize the logging system
/// Checks AKV_LOG_FILE environment variable to determine logging target
pub fn init_logging() -> Result<(), String> {
    INIT.call_once(|| {
        let log_file = std::env::var("AKV_LOG_FILE").ok();

        let mut builder =
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"));

        builder.format_timestamp_millis();

        // Custom format with timestamp and level
        builder.format(|buf, record| {
            writeln!(
                buf,
                "[{} {} {}:{}] {}",
                buf.timestamp_millis(),
                record.level(),
                record.module_path().unwrap_or("unknown"),
                record.line().unwrap_or(0),
                record.args()
            )
        });

        // Configure target (file or stderr)
        if let Some(ref path) = log_file {
            if !path.is_empty() {
                match std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                {
                    Ok(file) => {
                        builder.target(env_logger::Target::Pipe(Box::new(file)));
                        eprintln!("AKV Provider: Logging to file: {}", path);
                    }
                    Err(e) => {
                        eprintln!("AKV Provider: Failed to open log file {}: {}", path, e);
                        eprintln!("AKV Provider: Falling back to stderr logging");
                    }
                }
            }
        }

        builder.init();
    });

    Ok(())
}

/// Optimized trace logging - only evaluates arguments if trace is enabled
/// Use this for very verbose logging in hot paths
#[macro_export]
macro_rules! trace_opt {
    ($($arg:tt)*) => {
        if log::log_enabled!(log::Level::Trace) {
            log::trace!($($arg)*);
        }
    };
}

/// Optimized debug logging - only evaluates arguments if debug is enabled
/// Use this for debug logging with expensive string formatting
#[macro_export]
macro_rules! debug_opt {
    ($($arg:tt)*) => {
        if log::log_enabled!(log::Level::Debug) {
            log::debug!($($arg)*);
        }
    };
}

/// Log a debug message (kept for compatibility)
#[macro_export]
macro_rules! debug_log {
    ($($arg:tt)*) => {
        log::debug!($($arg)*);
    };
}

/// Log an info message
#[macro_export]
macro_rules! info_log {
    ($($arg:tt)*) => {
        log::info!($($arg)*);
    };
}

/// Log an error message
#[macro_export]
macro_rules! error_log {
    ($($arg:tt)*) => {
        log::error!($($arg)*);
    };
}
