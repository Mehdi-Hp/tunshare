//! Throughput accounting for the active sharing session.
//!
//! `netstat -ibn` returns cumulative byte counters since boot. We sample on
//! a tick, diff against the previous sample to compute an instantaneous rate,
//! and keep two ring buffers of recent rates for the sparkline.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// How many recent samples to keep per direction. Sized so that at the 1Hz
/// sample interval, the sparkline shows roughly a minute of history.
const HISTORY_LEN: usize = 60;

/// Eight-step block ramp used for sparkline rendering. Index 0 is reserved
/// for "no data / zero" rendered as a space, so callers should start at 1.
const SPARK_BARS: [char; 8] = [' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇'];

/// Per-direction throughput stats for an active sharing session.
#[derive(Debug, Default)]
pub struct TrafficStats {
    /// Cumulative ibytes at sharing start (subtracted to get session total).
    start_ibytes: Option<u64>,
    start_obytes: Option<u64>,
    /// Most recent raw sample.
    last_ibytes: Option<u64>,
    last_obytes: Option<u64>,
    last_sampled: Option<Instant>,

    /// Session totals (bytes since start), updated each sample.
    pub total_down: u64,
    pub total_up: u64,

    /// Current instantaneous rate in bytes/sec.
    pub rate_down: u64,
    pub rate_up: u64,

    /// Recent rate history (bytes/sec) — newest at the back.
    pub history_down: VecDeque<u64>,
    pub history_up: VecDeque<u64>,
}

impl TrafficStats {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a fresh `(ibytes, obytes)` reading. The first call only
    /// establishes a baseline; rates appear from the second sample on.
    ///
    /// If a sample comes in lower than the previous one (kernel counter
    /// reset, interface index reuse, integer wraparound), we rebaseline
    /// rather than underflow into a huge negative rate.
    pub fn record_sample(&mut self, ibytes: u64, obytes: u64, now: Instant) {
        if self.start_ibytes.is_none() {
            self.start_ibytes = Some(ibytes);
            self.start_obytes = Some(obytes);
        }

        if let (Some(prev_i), Some(prev_o), Some(prev_t)) =
            (self.last_ibytes, self.last_obytes, self.last_sampled)
        {
            let elapsed = now.saturating_duration_since(prev_t);
            let secs = elapsed.as_secs_f64().max(0.001);

            // Counter wrap / reset: rebaseline silently and emit a zero rate.
            if ibytes < prev_i || obytes < prev_o {
                self.start_ibytes = Some(ibytes);
                self.start_obytes = Some(obytes);
                self.rate_down = 0;
                self.rate_up = 0;
            } else {
                let delta_i = ibytes - prev_i;
                let delta_o = obytes - prev_o;
                self.rate_down = ((delta_i as f64) / secs) as u64;
                self.rate_up = ((delta_o as f64) / secs) as u64;
            }
        }

        if let (Some(si), Some(so)) = (self.start_ibytes, self.start_obytes) {
            self.total_down = ibytes.saturating_sub(si);
            self.total_up = obytes.saturating_sub(so);
        }

        push_capped(&mut self.history_down, self.rate_down, HISTORY_LEN);
        push_capped(&mut self.history_up, self.rate_up, HISTORY_LEN);

        self.last_ibytes = Some(ibytes);
        self.last_obytes = Some(obytes);
        self.last_sampled = Some(now);
    }

    /// Render the down-rate sparkline trimmed/right-aligned to `width` cells.
    pub fn sparkline_down(&self, width: usize) -> String {
        sparkline(&self.history_down, width)
    }

    /// Render the up-rate sparkline trimmed/right-aligned to `width` cells.
    pub fn sparkline_up(&self, width: usize) -> String {
        sparkline(&self.history_up, width)
    }
}

fn push_capped(buf: &mut VecDeque<u64>, value: u64, cap: usize) {
    if buf.len() == cap {
        buf.pop_front();
    }
    buf.push_back(value);
}

/// Build a right-aligned sparkline from the tail of `samples`, scaled so the
/// max sample in the visible window maps to the top step. Empty/all-zero
/// windows render as spaces to avoid showing a flat baseline that implies
/// "we're getting data, just none right now" when really nothing's measured.
fn sparkline(samples: &VecDeque<u64>, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    if samples.is_empty() {
        return " ".repeat(width);
    }

    // Take the most recent `width` samples.
    let take = width.min(samples.len());
    let start = samples.len() - take;
    let window: Vec<u64> = samples.iter().skip(start).copied().collect();

    let max = *window.iter().max().unwrap_or(&0);
    let pad = width - take;

    let mut out = String::with_capacity(width);
    for _ in 0..pad {
        out.push(' ');
    }
    if max == 0 {
        for _ in 0..take {
            out.push(' ');
        }
        return out;
    }

    // Scale to indices 1..=7 (reserve 0 for true zero rendered as space).
    for v in window {
        if v == 0 {
            out.push(' ');
        } else {
            // Map (0, max] → 1..=7. Use ceil-style mapping so the smallest
            // non-zero sample still produces a visible bar.
            let scaled = ((v as f64 / max as f64) * 7.0).ceil() as usize;
            let idx = scaled.clamp(1, 7);
            out.push(SPARK_BARS[idx]);
        }
    }
    out
}

/// Format a byte count as a short human string (e.g. "1.4 GB", "847 KB").
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.0} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Format a per-second rate as e.g. "2.4 MB/s".
pub fn format_rate(bytes_per_sec: u64) -> String {
    format!("{}/s", format_bytes(bytes_per_sec))
}

/// Minimum interval between traffic samples.
pub const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sample_only_establishes_baseline() {
        let mut t = TrafficStats::new();
        let now = Instant::now();
        t.record_sample(100, 50, now);
        assert_eq!(t.rate_down, 0);
        assert_eq!(t.rate_up, 0);
        assert_eq!(t.total_down, 0);
        assert_eq!(t.total_up, 0);
    }

    #[test]
    fn second_sample_computes_rate_and_total() {
        let mut t = TrafficStats::new();
        let now = Instant::now();
        t.record_sample(1_000, 500, now);
        t.record_sample(2_000, 700, now + Duration::from_secs(1));
        assert_eq!(t.rate_down, 1_000);
        assert_eq!(t.rate_up, 200);
        assert_eq!(t.total_down, 1_000);
        assert_eq!(t.total_up, 200);
    }

    #[test]
    fn counter_reset_rebaselines_without_underflow() {
        let mut t = TrafficStats::new();
        let now = Instant::now();
        t.record_sample(5_000, 2_000, now);
        t.record_sample(6_000, 2_500, now + Duration::from_secs(1));
        // Interface flap: counter goes back to small numbers.
        t.record_sample(100, 50, now + Duration::from_secs(2));
        assert_eq!(t.rate_down, 0);
        assert_eq!(t.rate_up, 0);
        // New baseline taken at 100/50 → total resets.
        t.record_sample(300, 150, now + Duration::from_secs(3));
        assert_eq!(t.total_down, 200);
        assert_eq!(t.total_up, 100);
    }

    #[test]
    fn sparkline_pads_left_when_history_shorter_than_width() {
        let mut t = TrafficStats::new();
        let now = Instant::now();
        t.record_sample(0, 0, now);
        t.record_sample(1_000, 0, now + Duration::from_secs(1));
        let s = t.sparkline_down(6);
        assert_eq!(s.chars().count(), 6);
        // First 4 cells are padding spaces.
        assert!(s.starts_with("    "));
    }

    #[test]
    fn format_bytes_picks_right_unit() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(2_048), "2 KB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.0 MB");
    }
}
