//! User preferences persistence.
//!
//! Saves/loads a small JSON config to `~/.config/tunshare/config.json`.
//! Failures are silently ignored (log at most) — the app always has sensible defaults.

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Persisted user preferences.
///
/// Every field has a serde default so that adding new fields later
/// doesn't break old config files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Whether to auto-start DHCP when sharing begins.
    /// Stored as user *intent* — the app still checks for dnsmasq at runtime.
    #[serde(default = "default_true")]
    pub dhcp_enabled: bool,

    /// Whether to auto-start NAT-PMP when sharing begins.
    #[serde(default = "default_true")]
    pub natpmp_enabled: bool,

    /// Custom DNS server override (None = auto-detect from VPN/system).
    #[serde(default)]
    pub custom_dns: Option<String>,
}

fn default_true() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Self {
            dhcp_enabled: true,
            natpmp_enabled: true,
            custom_dns: None,
        }
    }
}

impl Config {
    /// Config file path: `~/.config/tunshare/config.json`.
    ///
    /// Returns `None` if the home/config directory can't be determined.
    pub fn path() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("tunshare").join("config.json"))
    }

    /// Load config from disk, falling back to defaults on any error.
    pub fn load() -> Self {
        let Some(path) = Self::path() else {
            return Self::default();
        };

        let Ok(contents) = fs::read_to_string(&path) else {
            return Self::default();
        };

        serde_json::from_str(&contents).unwrap_or_default()
    }

    /// Save config to disk. Creates parent directories if needed.
    /// Logs nothing and never panics — this is best-effort.
    pub fn save(&self) {
        let Some(path) = Self::path() else {
            return;
        };

        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let Ok(json) = serde_json::to_string_pretty(self) else {
            return;
        };

        let _ = fs::write(&path, json);
    }
}
