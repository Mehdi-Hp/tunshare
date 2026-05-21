//! In-app log buffer: entry type and append helpers.
//!
//! Constructors for `LogEntry` (info/success/warning/error) live in
//! `ui::status` next to the log level enum, since the same module also
//! renders them.

use crate::ui::status::LogEntryLevel;

use super::App;

/// Bounded ring-buffer capacity for log entries.
pub(super) const MAX_LOG_ENTRIES: usize = 500;

/// One row in the status panel.
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: String,
    pub message: String,
    pub level: LogEntryLevel,
}

impl App {
    /// Append a log entry, evicting the oldest if at capacity.
    fn push_log(&mut self, entry: LogEntry) {
        if self.logs.len() >= MAX_LOG_ENTRIES {
            self.logs.pop_front();
        }
        self.logs.push_back(entry);
    }

    pub(super) fn log_info(&mut self, msg: impl Into<String>) {
        self.push_log(LogEntry::info(msg));
    }

    pub(super) fn log_success(&mut self, msg: impl Into<String>) {
        self.push_log(LogEntry::success(msg));
    }

    pub(super) fn log_warning(&mut self, msg: impl Into<String>) {
        self.push_log(LogEntry::warning(msg));
    }

    pub(super) fn log_error(&mut self, msg: impl Into<String>) {
        self.push_log(LogEntry::error(msg));
    }
}
