//! Diagnostic checks for "why isn't this working?"
//!
//! A single async engine that's shared by the in-app Doctor screen and
//! the `tunshare --doctor` CLI flag. Each check returns a `CheckResult`
//! with a short status (Pass/Warn/Fail), a remediation hint when not
//! passing, and a longer detail string for the expanded view.

use crate::error::Result;
use crate::system::{detect_lan_interfaces, detect_vpn_interfaces, run_cmd};

/// pf anchor name we use for NAT rules. Matches the value embedded in
/// `system::firewall::Firewall::generate_rules`.
const PF_ANCHOR_NAME: &str = "vpn_share";

/// Native NAT-PMP server port (RFC 6886).
const NATPMP_PORT: u16 = 5351;

/// Tools the app shells out to. These ship with macOS — missing any of
/// them means the environment is broken in ways we can't paper over.
const REQUIRED_BINARIES: &[&str] = &[
    "pfctl",
    "sysctl",
    "ifconfig",
    "networksetup",
    "scutil",
    "route",
];

/// Outcome of a single diagnostic check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckStatus {
    Pass,
    Warn { hint: String },
    Fail { hint: String },
}

/// One row in the diagnostic report.
#[derive(Debug, Clone)]
pub struct CheckResult {
    /// Short, scannable name shown in the checklist.
    pub name: String,
    pub status: CheckStatus,
    /// Multi-line detail shown when the row is expanded.
    pub detail: String,
}

impl CheckResult {
    fn pass(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: CheckStatus::Pass,
            detail: detail.into(),
        }
    }
    fn warn(name: impl Into<String>, hint: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: CheckStatus::Warn { hint: hint.into() },
            detail: detail.into(),
        }
    }
    fn fail(name: impl Into<String>, hint: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: CheckStatus::Fail { hint: hint.into() },
            detail: detail.into(),
        }
    }
}

/// Pass / Warn / Fail tally for the summary line.
#[derive(Debug, Clone, Copy, Default)]
pub struct CheckSummary {
    pub pass: usize,
    pub warn: usize,
    pub fail: usize,
}

impl CheckSummary {
    pub fn from_results(results: &[CheckResult]) -> Self {
        let mut s = Self::default();
        for r in results {
            match &r.status {
                CheckStatus::Pass => s.pass += 1,
                CheckStatus::Warn { .. } => s.warn += 1,
                CheckStatus::Fail { .. } => s.fail += 1,
            }
        }
        s
    }

    pub fn total(self) -> usize {
        self.pass + self.warn + self.fail
    }
}

/// Run all diagnostic checks. Most are independent and could run in
/// parallel, but the wall-clock for all of them serial is well under
/// 2 seconds in practice — keep it simple.
pub async fn run_checks() -> Vec<CheckResult> {
    vec![
        check_root(),
        check_required_binaries().await,
        check_dnsmasq_installed().await,
        check_ip_forwarding().await,
        check_pf_enabled().await,
        check_stale_anchor().await,
        check_internet_sharing().await,
        check_foreign_dnsmasq().await,
        check_natpmp_port().await,
        check_vpn_interface().await,
        check_lan_interface().await,
        check_config_writable(),
    ]
}

/// Flush the stale pf anchor so the Doctor's in-app cleanup action can
/// recover from a previous crashed run.
pub async fn flush_stale_anchor() -> Result<()> {
    run_cmd("pfctl", &["-a", PF_ANCHOR_NAME, "-F", "all"]).await?;
    Ok(())
}

// === Individual checks ===

fn check_root() -> CheckResult {
    // SAFETY: geteuid is signal-safe and always returns. No FFI invariants.
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        CheckResult::pass("Running as root", "geteuid() == 0")
    } else {
        CheckResult::fail(
            "Running as root",
            "Re-run with: sudo tunshare",
            "Most pf-based checks below will be inconclusive without root.",
        )
    }
}

async fn check_required_binaries() -> CheckResult {
    let mut missing = Vec::new();
    for bin in REQUIRED_BINARIES {
        if which(bin).await.is_none() {
            missing.push(*bin);
        }
    }
    if missing.is_empty() {
        CheckResult::pass("Required system tools", REQUIRED_BINARIES.join(", "))
    } else {
        CheckResult::fail(
            "Required system tools",
            "These ship with macOS — check $PATH",
            format!("missing: {}", missing.join(", ")),
        )
    }
}

async fn check_dnsmasq_installed() -> CheckResult {
    match which("dnsmasq").await {
        Some(path) => CheckResult::pass("dnsmasq installed (optional)", path),
        None => CheckResult::warn(
            "dnsmasq installed (optional)",
            "brew install dnsmasq — required for DHCP on connected devices",
            "not found in $PATH",
        ),
    }
}

async fn check_ip_forwarding() -> CheckResult {
    match run_cmd("sysctl", &["-n", "net.inet.ip.forwarding"]).await {
        Ok(o) => {
            let val = String::from_utf8_lossy(&o.stdout).trim().to_string();
            match val.as_str() {
                "0" => CheckResult::pass(
                    "IP forwarding pre-state",
                    "off (tunshare will enable on start, restore on exit)",
                ),
                "1" => CheckResult::warn(
                    "IP forwarding pre-state",
                    "Something else set this; tunshare will preserve the value on exit",
                    "net.inet.ip.forwarding == 1 before tunshare started",
                ),
                other => CheckResult::warn(
                    "IP forwarding pre-state",
                    "Unexpected sysctl value",
                    format!("got: {other}"),
                ),
            }
        }
        Err(e) => CheckResult::warn(
            "IP forwarding pre-state",
            "sysctl invocation failed",
            e.to_string(),
        ),
    }
}

async fn check_pf_enabled() -> CheckResult {
    match run_cmd("pfctl", &["-si"]).await {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if stdout.contains("Status: Enabled") {
                CheckResult::pass("pf is enabled", "pfctl reports Status: Enabled")
            } else if stdout.contains("Status: Disabled") {
                CheckResult::warn(
                    "pf is enabled",
                    "tunshare will enable pf on start",
                    "pf is currently disabled",
                )
            } else {
                CheckResult::warn(
                    "pf is enabled",
                    "Could not parse pfctl output (need root?)",
                    stdout.into_owned(),
                )
            }
        }
        Err(e) => CheckResult::warn(
            "pf is enabled",
            "pfctl invocation failed (need root?)",
            e.to_string(),
        ),
    }
}

async fn check_stale_anchor() -> CheckResult {
    match run_cmd("pfctl", &["-a", PF_ANCHOR_NAME, "-s", "nat"]).await {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if stdout.trim().is_empty() {
                CheckResult::pass(
                    format!("'{PF_ANCHOR_NAME}' pf anchor clean"),
                    "anchor has no NAT rules",
                )
            } else {
                CheckResult::fail(
                    format!("'{PF_ANCHOR_NAME}' pf anchor clean"),
                    "Press [c] to flush, or run: sudo pfctl -a vpn_share -F all",
                    stdout.into_owned(),
                )
            }
        }
        Err(e) => CheckResult::warn(
            format!("'{PF_ANCHOR_NAME}' pf anchor clean"),
            "pfctl invocation failed (need root?)",
            e.to_string(),
        ),
    }
}

async fn check_internet_sharing() -> CheckResult {
    let path = "/Library/Preferences/SystemConfiguration/com.apple.nat";
    match run_cmd("defaults", &["read", path, "NAT"]).await {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if stdout.contains("Enabled = 1") {
                CheckResult::fail(
                    "macOS Internet Sharing off",
                    "Disable in System Settings → General → Sharing → Internet Sharing",
                    "Internet Sharing is on and will conflict with tunshare's pf rules.",
                )
            } else {
                CheckResult::pass("macOS Internet Sharing off", "Enabled = 0 or unset")
            }
        }
        // No NAT dict at all means Internet Sharing has never been configured.
        Err(_) => CheckResult::pass(
            "macOS Internet Sharing off",
            "never configured (no NAT dict)",
        ),
    }
}

async fn check_foreign_dnsmasq() -> CheckResult {
    match run_cmd("pgrep", &["-x", "dnsmasq"]).await {
        Ok(o) if o.status.success() => {
            let pids: Vec<String> = String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .map(str::to_string)
                .collect();
            CheckResult::warn(
                "No foreign dnsmasq running",
                "May conflict with tunshare's DHCP server on port 53/67",
                format!("running PIDs: {}", pids.join(", ")),
            )
        }
        _ => CheckResult::pass("No foreign dnsmasq running", "pgrep found none"),
    }
}

async fn check_natpmp_port() -> CheckResult {
    let port_arg = format!("-iUDP:{NATPMP_PORT}");
    match run_cmd("lsof", &["-nP", &port_arg]).await {
        Ok(o) if o.status.success() && !o.stdout.is_empty() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            // First line is lsof's header; bound only if any process row follows.
            let rows: Vec<&str> = stdout.lines().skip(1).collect();
            if rows.is_empty() {
                CheckResult::pass(
                    format!("NAT-PMP port {NATPMP_PORT}/udp free"),
                    "no process bound",
                )
            } else {
                CheckResult::warn(
                    format!("NAT-PMP port {NATPMP_PORT}/udp free"),
                    "Another process holds the port; tunshare's NAT-PMP server will fail to start",
                    rows.join("\n"),
                )
            }
        }
        // lsof returns non-zero when nothing matches — that's the happy path.
        _ => CheckResult::pass(
            format!("NAT-PMP port {NATPMP_PORT}/udp free"),
            "no process bound",
        ),
    }
}

async fn check_vpn_interface() -> CheckResult {
    match detect_vpn_interfaces().await {
        Ok(ifaces) if !ifaces.is_empty() => {
            let names: Vec<String> = ifaces.iter().map(|i| i.name.clone()).collect();
            CheckResult::pass("VPN interface detected", names.join(", "))
        }
        Ok(_) => CheckResult::fail(
            "VPN interface detected",
            "Connect to your VPN before starting tunshare",
            "No utun* interface is up with an IPv4 address.",
        ),
        Err(e) => CheckResult::fail(
            "VPN interface detected",
            "Interface detection failed",
            e.to_string(),
        ),
    }
}

async fn check_lan_interface() -> CheckResult {
    match detect_lan_interfaces().await {
        Ok(ifaces) if !ifaces.is_empty() => {
            let names: Vec<String> = ifaces.iter().map(|i| i.name.clone()).collect();
            CheckResult::pass("LAN interface detected", names.join(", "))
        }
        Ok(_) => CheckResult::fail(
            "LAN interface detected",
            "An en* interface (ethernet / USB ethernet) must be up with an IPv4 address",
            "No en* interface is up with an IPv4 address.",
        ),
        Err(e) => CheckResult::fail(
            "LAN interface detected",
            "Interface detection failed",
            e.to_string(),
        ),
    }
}

fn check_config_writable() -> CheckResult {
    let Some(path) = dirs::config_dir().map(|d| d.join("tunshare")) else {
        return CheckResult::warn(
            "Config dir writable",
            "Could not determine config directory ($HOME unset?)",
            "dirs::config_dir() returned None",
        );
    };
    match std::fs::create_dir_all(&path) {
        Ok(()) => CheckResult::pass("Config dir writable", path.display().to_string()),
        Err(e) => CheckResult::fail(
            "Config dir writable",
            "Check filesystem permissions on $XDG_CONFIG_HOME",
            format!("{}: {}", path.display(), e),
        ),
    }
}

// === Helpers ===

async fn which(bin: &str) -> Option<String> {
    let output = run_cmd("which", &[bin]).await.ok()?;
    if !output.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!s.is_empty()).then_some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_counts_by_status() {
        let results = vec![
            CheckResult::pass("a", "ok"),
            CheckResult::pass("b", "ok"),
            CheckResult::warn("c", "do thing", "detail"),
            CheckResult::fail("d", "fix it", "detail"),
        ];
        let s = CheckSummary::from_results(&results);
        assert_eq!(s.pass, 2);
        assert_eq!(s.warn, 1);
        assert_eq!(s.fail, 1);
        assert_eq!(s.total(), 4);
    }
}
