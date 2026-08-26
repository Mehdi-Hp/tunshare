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

/// Default StevenBlack unified hosts (ads/trackers/malware).
pub const DEFAULT_BLOCK_STEVENBLACK: &str =
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts";
/// Iran-v2ray ads/malware/phishing lists, unioned with StevenBlack.
pub const DEFAULT_BLOCK_ADS: &str =
    "https://raw.githubusercontent.com/chocolate4u/Iran-v2ray-rules/release/ads.txt";
pub const DEFAULT_BLOCK_MALWARE: &str =
    "https://raw.githubusercontent.com/chocolate4u/Iran-v2ray-rules/release/malware.txt";
pub const DEFAULT_BLOCK_PHISHING: &str =
    "https://raw.githubusercontent.com/chocolate4u/Iran-v2ray-rules/release/phishing.txt";
/// HaGeZi Light — ads/trackers. Off until you turn it on (overlaps StevenBlack).
pub const DEFAULT_BLOCK_HAGEZI_LIGHT: &str =
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt";
/// HaGeZi threat-intel feed (malware/phishing/scam). Off until you turn it on.
pub const DEFAULT_BLOCK_HAGEZI_TIF: &str =
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt";
/// 1Hosts Lite — ads/trackers. Off until you turn it on.
pub const DEFAULT_BLOCK_1HOSTS_LITE: &str =
    "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/hosts.txt";
/// Phishing Army. Off until you turn it on.
pub const DEFAULT_BLOCK_PHISHING_ARMY: &str =
    "https://phishing.army/download/phishing_army_blocklist.txt";
/// Iran direct-connect domains — routed out the WAN uplink, not the VPN.
pub const DEFAULT_ALLOW_IR: &str =
    "https://raw.githubusercontent.com/chocolate4u/Iran-v2ray-rules/release/ir.txt";
/// China direct-connect domains (Loyalsoldier). Off until you turn it on.
pub const DEFAULT_ALLOW_CN: &str =
    "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/china-list.txt";

const DEFAULT_REFRESH_HOURS: u32 = 24;

struct BundledSource {
    url: &'static str,
    default_enabled: bool,
}

fn builtin_block() -> &'static [BundledSource] {
    &[
        BundledSource {
            url: DEFAULT_BLOCK_STEVENBLACK,
            default_enabled: true,
        },
        BundledSource {
            url: DEFAULT_BLOCK_ADS,
            default_enabled: true,
        },
        BundledSource {
            url: DEFAULT_BLOCK_MALWARE,
            default_enabled: true,
        },
        BundledSource {
            url: DEFAULT_BLOCK_PHISHING,
            default_enabled: true,
        },
        BundledSource {
            url: DEFAULT_BLOCK_HAGEZI_LIGHT,
            default_enabled: false,
        },
        BundledSource {
            url: DEFAULT_BLOCK_HAGEZI_TIF,
            default_enabled: false,
        },
        BundledSource {
            url: DEFAULT_BLOCK_1HOSTS_LITE,
            default_enabled: false,
        },
        BundledSource {
            url: DEFAULT_BLOCK_PHISHING_ARMY,
            default_enabled: false,
        },
    ]
}

fn builtin_allow() -> &'static [BundledSource] {
    &[
        BundledSource {
            url: DEFAULT_ALLOW_IR,
            default_enabled: true,
        },
        BundledSource {
            url: DEFAULT_ALLOW_CN,
            default_enabled: false,
        },
    ]
}

fn default_block_sources() -> Vec<ListSource> {
    builtin_block()
        .iter()
        .map(|source| ListSource::builtin(source.url, source.default_enabled))
        .collect()
}

fn default_allow_sources() -> Vec<ListSource> {
    builtin_allow()
        .iter()
        .map(|source| ListSource::builtin(source.url, source.default_enabled))
        .collect()
}

fn default_refresh_hours() -> u32 {
    DEFAULT_REFRESH_HOURS
}

fn source_enabled_default() -> bool {
    true
}

fn skip_empty_name(name: &Option<String>) -> bool {
    name.as_ref().is_none_or(|s| s.is_empty())
}

/// Wire format: a bare URL string (legacy) or `{url, enabled, name}`.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum ListSourceWire {
    Url(String),
    Object {
        url: String,
        #[serde(default = "source_enabled_default")]
        enabled: bool,
        #[serde(default)]
        name: Option<String>,
    },
}

impl From<ListSourceWire> for ListSource {
    fn from(wire: ListSourceWire) -> Self {
        match wire {
            ListSourceWire::Url(url) => Self {
                url,
                enabled: true,
                name: None,
            },
            ListSourceWire::Object { url, enabled, name } => Self {
                url,
                enabled,
                name: name.filter(|s| !s.is_empty()),
            },
        }
    }
}

/// One URL in a block or WAN-bypass job. Builtins can be disabled, not deleted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(from = "ListSourceWire")]
pub struct ListSource {
    pub url: String,
    #[serde(default = "source_enabled_default")]
    pub enabled: bool,
    /// Custom display name. Builtins ignore this and keep baked labels.
    #[serde(default, skip_serializing_if = "skip_empty_name")]
    pub name: Option<String>,
}

impl ListSource {
    fn builtin(url: &str, enabled: bool) -> Self {
        Self {
            url: url.to_string(),
            enabled,
            name: None,
        }
    }

    pub fn is_builtin(&self) -> bool {
        is_builtin_url(&self.url)
    }

    /// Short row label. Named customs win; builtins keep baked names.
    pub fn label(&self) -> String {
        if !self.is_builtin() {
            if let Some(name) = self
                .name
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                return name.to_string();
            }
        }
        source_label(&self.url)
    }
}

pub fn is_builtin_url(url: &str) -> bool {
    builtin_block()
        .iter()
        .chain(builtin_allow())
        .any(|source| source.url == url)
}

fn is_http_url(url: &str) -> bool {
    let url = url.trim();
    url.starts_with("https://") || url.starts_with("http://")
}

pub fn source_label(url: &str) -> String {
    match url {
        DEFAULT_BLOCK_STEVENBLACK => "StevenBlack hosts".into(),
        DEFAULT_BLOCK_ADS => "IR ads".into(),
        DEFAULT_BLOCK_MALWARE => "IR malware".into(),
        DEFAULT_BLOCK_PHISHING => "IR phishing".into(),
        DEFAULT_BLOCK_HAGEZI_LIGHT => "HaGeZi Light".into(),
        DEFAULT_BLOCK_HAGEZI_TIF => "HaGeZi TIF".into(),
        DEFAULT_BLOCK_1HOSTS_LITE => "1Hosts Lite".into(),
        DEFAULT_BLOCK_PHISHING_ARMY => "Phishing Army".into(),
        DEFAULT_ALLOW_IR => "IR direct".into(),
        DEFAULT_ALLOW_CN => "CN direct".into(),
        other => custom_source_label(other),
    }
}

fn custom_source_label(url: &str) -> String {
    let trimmed = url
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    if trimmed.chars().count() <= 40 {
        trimmed.to_string()
    } else {
        let mut s: String = trimmed.chars().take(39).collect();
        s.push('…');
        s
    }
}

/// One URL-driven domain list. `enabled` is off on first run so sharing
/// still works without a WAN uplink or a GitHub fetch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListSetting {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub sources: Vec<ListSource>,
    #[serde(default = "default_refresh_hours")]
    pub refresh_interval_hours: u32,
}

impl ListSetting {
    fn block_default() -> Self {
        Self {
            enabled: false,
            sources: default_block_sources(),
            refresh_interval_hours: DEFAULT_REFRESH_HOURS,
        }
    }

    fn allow_default() -> Self {
        Self {
            enabled: false,
            sources: default_allow_sources(),
            refresh_interval_hours: DEFAULT_REFRESH_HOURS,
        }
    }

    pub fn enabled_urls(&self) -> Vec<String> {
        self.sources
            .iter()
            .filter(|s| s.enabled)
            .map(|s| s.url.clone())
            .collect()
    }

    pub fn add_custom(&mut self, url: String, name: Option<String>) -> Result<(), String> {
        if !is_http_url(&url) {
            return Err("URL must start with http:// or https://".into());
        }
        if self.sources.iter().any(|s| s.url == url) {
            return Err("that URL is already in this list".into());
        }
        let name = name.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        self.sources.push(ListSource {
            url,
            enabled: true,
            name,
        });
        Ok(())
    }

    /// Remove a custom source. Builtins stay.
    pub fn remove_custom(&mut self, index: usize) -> Option<ListSource> {
        let source = self.sources.get(index)?;
        if source.is_builtin() {
            return None;
        }
        Some(self.sources.remove(index))
    }

    fn ensure_builtins(&mut self, builtins: &[BundledSource]) {
        let existing = std::mem::take(&mut self.sources);
        let mut by_url = std::collections::HashMap::new();
        let mut customs = Vec::new();
        for source in existing {
            if builtins.iter().any(|bundled| bundled.url == source.url) {
                by_url.insert(source.url.clone(), source);
            } else {
                customs.push(source);
            }
        }
        let mut ordered = Vec::new();
        for bundled in builtins {
            ordered.push(
                by_url
                    .remove(bundled.url)
                    .unwrap_or_else(|| ListSource::builtin(bundled.url, bundled.default_enabled)),
            );
        }
        ordered.extend(customs);
        self.sources = ordered;
    }
}

impl Default for ListSetting {
    fn default() -> Self {
        Self {
            enabled: false,
            sources: Vec::new(),
            refresh_interval_hours: DEFAULT_REFRESH_HOURS,
        }
    }
}

/// Blocklist + allowlist. Independent toggles.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListsConfig {
    #[serde(default = "ListSetting::block_default")]
    pub block: ListSetting,
    #[serde(default = "ListSetting::allow_default")]
    pub allow: ListSetting,
}

impl Default for ListsConfig {
    fn default() -> Self {
        Self {
            block: ListSetting::block_default(),
            allow: ListSetting::allow_default(),
        }
    }
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

    /// Blocklist (DNS NXDOMAIN) and allowlist (WAN split-tunnel).
    #[serde(default)]
    pub lists: ListsConfig,
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
            lists: ListsConfig::default(),
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
        cfg.fill_list_source_defaults();
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

    fn fill_list_source_defaults(&mut self) {
        self.lists.block.ensure_builtins(builtin_block());
        self.lists.allow.ensure_builtins(builtin_allow());
        if self.lists.block.refresh_interval_hours == 0 {
            self.lists.block.refresh_interval_hours = DEFAULT_REFRESH_HOURS;
        }
        if self.lists.allow.refresh_interval_hours == 0 {
            self.lists.allow.refresh_interval_hours = DEFAULT_REFRESH_HOURS;
        }
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
        // Missing `lists` must land on baked-in defaults, both off.
        assert!(!cfg.lists.block.enabled);
        assert!(!cfg.lists.allow.enabled);
        assert_eq!(cfg.lists.block.sources, default_block_sources());
        assert_eq!(cfg.lists.allow.sources, default_allow_sources());
    }

    #[test]
    fn lists_round_trip_preserves_enabled_and_custom_urls() {
        let mut cfg = Config::default();
        cfg.lists.block.enabled = true;
        cfg.lists
            .block
            .add_custom("https://example.com/hosts".into(), None)
            .unwrap();
        let json = serde_json::to_string(&cfg).unwrap();
        let loaded: Config = serde_json::from_str(&json).unwrap();
        assert!(loaded.lists.block.enabled);
        assert!(loaded
            .lists
            .block
            .sources
            .iter()
            .any(|s| s.url == "https://example.com/hosts" && s.enabled));
        assert!(!loaded.lists.allow.enabled);
        assert_eq!(
            loaded.lists.block.sources.len(),
            default_block_sources().len() + 1
        );
    }

    #[test]
    fn legacy_string_sources_migrate_to_enabled_objects() {
        let json = r#"{
            "lists": {
                "block": {
                    "enabled": true,
                    "sources": ["https://example.com/hosts"]
                }
            }
        }"#;
        let mut cfg: Config = serde_json::from_str(json).unwrap();
        cfg.fill_list_source_defaults();
        assert!(cfg.lists.block.enabled);
        assert_eq!(cfg.lists.block.sources[0].url, DEFAULT_BLOCK_STEVENBLACK);
        assert!(cfg.lists.block.sources[0].enabled);
        let custom = cfg
            .lists
            .block
            .sources
            .iter()
            .find(|s| s.url == "https://example.com/hosts")
            .unwrap();
        assert!(custom.enabled);
        assert!(custom.name.is_none());
        assert!(!custom.is_builtin());
        assert_eq!(cfg.lists.allow.sources.len(), default_allow_sources().len());
        assert_eq!(cfg.lists.allow.sources[0].url, DEFAULT_ALLOW_IR);
        let china = cfg
            .lists
            .allow
            .sources
            .iter()
            .find(|s| s.url == DEFAULT_ALLOW_CN)
            .unwrap();
        assert!(!china.enabled);
    }

    #[test]
    fn enabled_urls_skips_disabled_sources() {
        let mut setting = ListSetting::block_default();
        setting.sources[0].enabled = false;
        let urls = setting.enabled_urls();
        assert!(!urls.iter().any(|url| url == DEFAULT_BLOCK_STEVENBLACK));
        assert_eq!(urls.len(), 3);
    }

    #[test]
    fn add_custom_rejects_non_http() {
        let mut setting = ListSetting::block_default();
        assert!(setting
            .add_custom("ftp://example.com/hosts".into(), None)
            .is_err());
        assert!(setting
            .add_custom("example.com/hosts".into(), None)
            .is_err());
        assert!(setting
            .add_custom("https://example.com/hosts".into(), None)
            .is_ok());
    }

    #[test]
    fn remove_custom_keeps_builtins() {
        let mut setting = ListSetting::block_default();
        setting
            .add_custom("https://example.com/hosts".into(), None)
            .unwrap();
        let custom_idx = setting.sources.len() - 1;
        assert!(setting.remove_custom(0).is_none());
        let removed = setting.remove_custom(custom_idx).unwrap();
        assert_eq!(removed.url, "https://example.com/hosts");
        assert_eq!(setting.sources.len(), default_block_sources().len());
    }

    #[test]
    fn named_custom_round_trips_and_labels() {
        let mut setting = ListSetting::block_default();
        setting
            .add_custom(
                "https://example.com/hosts".into(),
                Some("  Ads extra  ".into()),
            )
            .unwrap();
        let custom = setting.sources.last().unwrap();
        assert_eq!(custom.name.as_deref(), Some("Ads extra"));
        assert_eq!(custom.label(), "Ads extra");
        let json = serde_json::to_string(&setting).unwrap();
        assert!(json.contains("\"name\":\"Ads extra\""));
        let loaded: ListSetting = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.sources.last().unwrap().label(), "Ads extra");

        setting
            .add_custom("https://example.com/other".into(), Some("   ".into()))
            .unwrap();
        assert!(setting.sources.last().unwrap().name.is_none());
        assert_eq!(
            setting.sources.last().unwrap().label(),
            custom_source_label("https://example.com/other")
        );

        setting.sources[0].name = Some("ignored on builtin".into());
        assert_eq!(setting.sources[0].label(), "StevenBlack hosts");
    }

    #[test]
    fn extra_builtins_refill_stay_off() {
        let json = r#"{
            "lists": {
                "block": { "enabled": true, "sources": [] },
                "allow": { "enabled": false, "sources": [] }
            }
        }"#;
        let mut cfg: Config = serde_json::from_str(json).unwrap();
        cfg.fill_list_source_defaults();
        let tif = cfg
            .lists
            .block
            .sources
            .iter()
            .find(|s| s.url == DEFAULT_BLOCK_HAGEZI_TIF)
            .unwrap();
        assert!(!tif.enabled);
        let light = cfg
            .lists
            .block
            .sources
            .iter()
            .find(|s| s.url == DEFAULT_BLOCK_HAGEZI_LIGHT)
            .unwrap();
        assert!(!light.enabled);
        let hosts = cfg
            .lists
            .block
            .sources
            .iter()
            .find(|s| s.url == DEFAULT_BLOCK_1HOSTS_LITE)
            .unwrap();
        assert!(!hosts.enabled);
        let army = cfg
            .lists
            .block
            .sources
            .iter()
            .find(|s| s.url == DEFAULT_BLOCK_PHISHING_ARMY)
            .unwrap();
        assert!(!army.enabled);
        assert!(
            cfg.lists
                .block
                .sources
                .iter()
                .find(|s| s.url == DEFAULT_BLOCK_STEVENBLACK)
                .unwrap()
                .enabled
        );
        let china = cfg
            .lists
            .allow
            .sources
            .iter()
            .find(|s| s.url == DEFAULT_ALLOW_CN)
            .unwrap();
        assert!(!china.enabled);
        assert!(
            cfg.lists
                .allow
                .sources
                .iter()
                .find(|s| s.url == DEFAULT_ALLOW_IR)
                .unwrap()
                .enabled
        );
    }
}
