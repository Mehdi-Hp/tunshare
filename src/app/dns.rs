//! DNS configuration, presets, edit-mode state, and picker indexing.

use crate::config::DNS_HISTORY_MAX;

use super::App;

/// A DNS preset entry.
#[derive(Debug, Clone)]
pub struct DnsPreset {
    pub name: &'static str,
    pub ip: &'static str,
}

/// Well-known DNS presets.
pub const DNS_PRESETS: &[DnsPreset] = &[
    DnsPreset {
        name: "Cloudflare",
        ip: "1.1.1.1",
    },
    DnsPreset {
        name: "Google",
        ip: "8.8.8.8",
    },
    DnsPreset {
        name: "Quad9",
        ip: "9.9.9.9",
    },
    DnsPreset {
        name: "OpenDNS",
        ip: "208.67.222.222",
    },
];

/// DNS edit sub-mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsEditMode {
    SelectingPreset,
    CustomInput,
}

/// DNS configuration and edit state.
pub struct DnsConfig {
    /// DNS servers discovered for the VPN.
    pub vpn_servers: Vec<String>,
    /// System default DNS servers.
    pub system_servers: Vec<String>,
    /// User-specified custom DNS server (overrides auto-detected).
    pub custom: Option<String>,
    /// Recently-used custom DNS servers, most-recent first, capped at
    /// [`DNS_HISTORY_MAX`]. Persisted in the config file.
    pub history: Vec<String>,
    /// Text input buffer for DNS editing.
    pub input_buffer: String,
    /// DNS edit sub-mode (preset list vs custom input).
    pub edit_mode: DnsEditMode,
    /// Selected index in the picker list. Layout (no divider rows):
    /// `[Auto-detect, ...presets, ...history, Custom...]`
    pub preset_selected: usize,
}

impl DnsConfig {
    pub(super) fn new(custom: Option<String>, history: Vec<String>) -> Self {
        Self {
            vpn_servers: Vec::new(),
            system_servers: Vec::new(),
            custom,
            history,
            input_buffer: String::new(),
            edit_mode: DnsEditMode::SelectingPreset,
            preset_selected: 0,
        }
    }

    /// Move `value` to the front of history, dedup, cap at [`DNS_HISTORY_MAX`].
    /// No-op if `value` matches a built-in preset (those are always available).
    pub fn promote_to_history(&mut self, value: &str) {
        if DNS_PRESETS.iter().any(|p| p.ip == value) {
            return;
        }
        self.history.retain(|h| h != value);
        self.history.insert(0, value.to_string());
        self.history.truncate(DNS_HISTORY_MAX);
    }

    /// Get the effective DNS servers (custom > vpn > system).
    pub fn effective(&self) -> Vec<String> {
        if let Some(ref dns) = self.custom {
            vec![dns.clone()]
        } else if !self.vpn_servers.is_empty() {
            self.vpn_servers.clone()
        } else {
            self.system_servers.clone()
        }
    }

    /// Get the source label for the current DNS.
    pub fn source(&self) -> &'static str {
        if self.custom.is_some() {
            "custom"
        } else if !self.vpn_servers.is_empty() {
            "vpn"
        } else if !self.system_servers.is_empty() {
            "system"
        } else {
            "none"
        }
    }
}

impl App {
    /// Total number of selectable rows in the picker.
    /// Layout: `[Auto-detect, ...presets, ...history, Custom...]`.
    pub(super) fn dns_preset_count(&self) -> usize {
        1 + DNS_PRESETS.len() + self.dns.history.len() + 1
    }

    /// Index of the first history row (one past the last preset row).
    pub(super) fn dns_history_start(&self) -> usize {
        1 + DNS_PRESETS.len()
    }

    /// Index of the "Custom..." row.
    pub fn dns_custom_input_idx(&self) -> usize {
        self.dns_history_start() + self.dns.history.len()
    }

    /// If the given picker row points into history, return its history index.
    pub fn dns_history_idx(&self, row: usize) -> Option<usize> {
        let start = self.dns_history_start();
        let end = start + self.dns.history.len();
        (row >= start && row < end).then(|| row - start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_history_promotion_dedups_and_caps() {
        let mut cfg = DnsConfig::new(None, Vec::new());
        // Build a 12-entry history; should cap to DNS_HISTORY_MAX (10).
        for i in 0..12 {
            cfg.promote_to_history(&format!("10.0.0.{i}"));
        }
        assert_eq!(cfg.history.len(), DNS_HISTORY_MAX);
        // Most recent first.
        assert_eq!(cfg.history[0], "10.0.0.11");
        assert_eq!(cfg.history[DNS_HISTORY_MAX - 1], "10.0.0.2");

        // Promoting an existing value moves it to the front without duplicating.
        cfg.promote_to_history("10.0.0.5");
        assert_eq!(cfg.history[0], "10.0.0.5");
        assert_eq!(cfg.history.len(), DNS_HISTORY_MAX);
        assert_eq!(cfg.history.iter().filter(|h| *h == "10.0.0.5").count(), 1);
    }

    #[test]
    fn dns_history_skips_built_in_presets() {
        let mut cfg = DnsConfig::new(None, Vec::new());
        // 1.1.1.1 is the Cloudflare preset — it shouldn't enter history.
        cfg.promote_to_history("1.1.1.1");
        cfg.promote_to_history("10.0.0.5");
        assert_eq!(cfg.history, vec!["10.0.0.5".to_string()]);
    }

    #[test]
    fn dns_picker_history_indexing() {
        let mut app = App::new();
        app.dns.history = vec!["10.0.0.5".to_string(), "192.168.1.1".to_string()];

        // Layout: [Auto(0), Cloudflare(1), Google(2), Quad9(3), OpenDNS(4),
        //          10.0.0.5(5), 192.168.1.1(6), Custom...(7)]
        let preset_count = 4; // matches DNS_PRESETS const length
        assert_eq!(app.dns_history_idx(preset_count), None); // last preset
        assert_eq!(app.dns_history_idx(1 + preset_count), Some(0));
        assert_eq!(app.dns_history_idx(2 + preset_count), Some(1));
        assert_eq!(app.dns_custom_input_idx(), 3 + preset_count);
        assert_eq!(app.dns_history_idx(app.dns_custom_input_idx()), None);
    }
}
