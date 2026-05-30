//! User preferences persistence.
//!
//! Saves/loads a small JSON config to `~/.config/tunshare/config.json`.
//! Failures are silently ignored (log at most) — the app always has sensible defaults.

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::health::VpnDropStrategy;

/// Maximum number of remembered custom DNS entries.
pub const DNS_HISTORY_MAX: usize = 10;

/// Minimum acceptable MTU. IPv4 RFC 791 floor; smaller values break PMTUD
/// and most stacks reject them outright.
pub const MTU_MIN: u16 = 576;
/// Maximum acceptable MTU. Jumbo-frame upper bound; macOS `ifconfig` rejects
/// larger values on most interface types.
pub const MTU_MAX: u16 = 9000;

/// Tunnel MTU policy — the value the pf scrub `max-mss` clamp derives from.
///
/// `Auto` (default) measures the real path MTU with an active probe at session
/// start, so the clamp tracks encapsulation overhead a tunnel's interface MTU
/// hides. `Fixed(n)` pins an explicit tunnel MTU (clamp = `n - 40`), skipping
/// the probe.
///
/// The old `match_vpn` policy is gone — it copied the tunnel's (often inflated)
/// interface MTU, which is exactly what `Auto` now improves on. Configs that
/// still carry it deserialize to `Auto` via the serde alias.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(tag = "mode", content = "value", rename_all = "snake_case")]
pub enum LanMtu {
    #[default]
    #[serde(alias = "match_vpn")]
    Auto,
    Fixed(u16),
}

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

    /// Currently-selected custom DNS server (`None` = auto-detect from
    /// VPN/system). Mirrors `App::dns.custom` on save.
    #[serde(default)]
    pub custom_dns: Option<String>,

    /// Recently-used custom DNS servers, most-recent first, capped at
    /// [`DNS_HISTORY_MAX`]. The picker shows these as a recall list under
    /// the built-in presets. Orthogonal to `custom_dns` (the active value).
    #[serde(default)]
    pub dns_history: Vec<String>,

    /// What to do when the VPN interface drops mid-session.
    #[serde(default)]
    pub vpn_drop_strategy: VpnDropStrategy,

    /// Tunnel MTU policy driving the pf scrub MSS clamp. See [`LanMtu`].
    #[serde(default)]
    pub lan_mtu: LanMtu,
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
            dns_history: Vec::new(),
            vpn_drop_strategy: VpnDropStrategy::default(),
            lan_mtu: LanMtu::default(),
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
    ///
    /// Migrates a v0.1 config that only had `custom_dns` set by populating
    /// `dns_history` with that value, so the previous picker entry shows up.
    pub fn load() -> Self {
        let Some(path) = Self::path() else {
            return Self::default();
        };
        let Ok(contents) = fs::read_to_string(&path) else {
            return Self::default();
        };
        let mut cfg: Config = serde_json::from_str(&contents).unwrap_or_default();
        if let Some(active) = cfg.custom_dns.as_deref() {
            if !active.is_empty() && !cfg.dns_history.iter().any(|h| h == active) {
                cfg.dns_history.insert(0, active.to_string());
                cfg.dns_history.truncate(DNS_HISTORY_MAX);
            }
        }
        cfg
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_match_vpn_migrates_to_auto() {
        let mtu: LanMtu = serde_json::from_str(r#"{"mode":"match_vpn"}"#).unwrap();
        assert_eq!(mtu, LanMtu::Auto);
    }

    #[test]
    fn lan_mtu_variants_round_trip() {
        let auto: LanMtu = serde_json::from_str(r#"{"mode":"auto"}"#).unwrap();
        assert_eq!(auto, LanMtu::Auto);
        let fixed: LanMtu = serde_json::from_str(r#"{"mode":"fixed","value":1440}"#).unwrap();
        assert_eq!(fixed, LanMtu::Fixed(1440));
    }

    #[test]
    fn legacy_config_with_match_vpn_keeps_other_prefs() {
        // A config written by an older version: the dropped `match_vpn` token
        // must migrate in place, not discard the surrounding preferences.
        let json = r#"{
            "dhcp_enabled": false,
            "natpmp_enabled": false,
            "custom_dns": "1.1.1.1",
            "dns_history": ["1.1.1.1", "8.8.8.8"],
            "lan_mtu": {"mode": "match_vpn"}
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.lan_mtu, LanMtu::Auto);
        assert!(!cfg.dhcp_enabled);
        assert!(!cfg.natpmp_enabled);
        assert_eq!(cfg.custom_dns.as_deref(), Some("1.1.1.1"));
        assert_eq!(cfg.dns_history, vec!["1.1.1.1", "8.8.8.8"]);
    }
}
