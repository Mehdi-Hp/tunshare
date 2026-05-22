//! Diagnostic checks for "why isn't this working?"
//!
//! A single async engine that's shared by the in-app Doctor screen and
//! the `tunshare --doctor` CLI flag. Each check returns a `CheckResult`
//! with a short status (Pass/Warn/Fail), a remediation hint when not
//! passing, and a longer detail string for the expanded view.

use crate::error::Result;
use crate::system::{detect_lan_interfaces, detect_vpn_interfaces, run_cmd, same_ipv4_network};

/// pf anchor name we use for NAT rules. Matches the value embedded in
/// `system::firewall::Firewall::generate_rules`.
const PF_ANCHOR_NAME: &str = "vpn_share";

/// Native NAT-PMP server port (RFC 6886).
const NATPMP_PORT: u16 = 5351;

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
    /// Single-line value rendered inline next to the name. May be empty.
    pub detail: String,
    /// UI grouping label (e.g. "Environment"). Set by `run_checks`.
    pub group: &'static str,
}

impl CheckResult {
    fn pass(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: CheckStatus::Pass,
            detail: detail.into(),
            group: "",
        }
    }
    fn warn(name: impl Into<String>, hint: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: CheckStatus::Warn { hint: hint.into() },
            detail: detail.into(),
            group: "",
        }
    }
    fn fail(name: impl Into<String>, hint: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: CheckStatus::Fail { hint: hint.into() },
            detail: detail.into(),
            group: "",
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
    let mut results = Vec::new();

    push_group(
        &mut results,
        "Environment",
        vec![
            check_dnsmasq_installed().await,
            check_stale_anchor().await,
            check_internet_sharing().await,
        ],
    );
    push_group(
        &mut results,
        "Port conflicts",
        vec![check_foreign_dnsmasq().await, check_natpmp_port().await],
    );
    push_group(&mut results, "Interfaces", {
        let mut v = vec![check_vpn_interface().await];
        v.extend(check_lan_interfaces().await);
        v
    });

    results
}

fn push_group(out: &mut Vec<CheckResult>, group: &'static str, mut items: Vec<CheckResult>) {
    for item in &mut items {
        item.group = group;
    }
    out.extend(items);
}

/// Flush the stale pf anchor so the Doctor's in-app cleanup action can
/// recover from a previous crashed run.
pub async fn flush_stale_anchor() -> Result<()> {
    run_cmd("pfctl", &["-a", PF_ANCHOR_NAME, "-F", "all"]).await?;
    Ok(())
}

// === Individual checks ===

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

async fn check_stale_anchor() -> CheckResult {
    match run_cmd("pfctl", &["-a", PF_ANCHOR_NAME, "-s", "nat"]).await {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if stdout.trim().is_empty() {
                CheckResult::pass(format!("{PF_ANCHOR_NAME} pf anchor clean"), "")
            } else {
                CheckResult::fail(
                    format!("{PF_ANCHOR_NAME} pf anchor clean"),
                    "Press [c] to flush, or run: sudo pfctl -a vpn_share -F all",
                    stdout.into_owned(),
                )
            }
        }
        Err(e) => CheckResult::warn(
            format!("{PF_ANCHOR_NAME} pf anchor clean"),
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
                CheckResult::pass("macOS Internet Sharing off", "")
            }
        }
        // No NAT dict at all means Internet Sharing has never been configured.
        Err(_) => CheckResult::pass("macOS Internet Sharing off", ""),
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
        _ => CheckResult::pass("No foreign dnsmasq running", ""),
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
                CheckResult::pass(format!("NAT-PMP port {NATPMP_PORT}/udp free"), "")
            } else {
                CheckResult::warn(
                    format!("NAT-PMP port {NATPMP_PORT}/udp free"),
                    "Another process holds the port; tunshare's NAT-PMP server will fail to start",
                    rows.join("\n"),
                )
            }
        }
        // lsof returns non-zero when nothing matches — that's the happy path.
        _ => CheckResult::pass(format!("NAT-PMP port {NATPMP_PORT}/udp free"), ""),
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

/// One row per detected LAN interface. Each row reports whether that LAN
/// is usable for tunshare — currently, "unusable" means it shares a subnet
/// with another LAN, which would break routing if selected.
async fn check_lan_interfaces() -> Vec<CheckResult> {
    let ifaces = match detect_lan_interfaces().await {
        Ok(v) => v,
        Err(e) => {
            return vec![CheckResult::fail(
                "LAN interfaces",
                "Interface detection failed",
                e.to_string(),
            )];
        }
    };

    if ifaces.is_empty() {
        return vec![CheckResult::fail(
            "LAN interfaces",
            "Connect a wired adapter (ethernet / USB ethernet). Wi-Fi is excluded — the Mac would be a client, not an AP",
            "No wired en* interface is up with an IPv4 address.",
        )];
    }

    ifaces
        .iter()
        .map(|iface| {
            let ip = iface
                .ipv4_address
                .map(|a| a.to_string())
                .unwrap_or_else(|| "no IPv4".into());
            let prefix = iface
                .ipv4_netmask
                .map(|m| format!("/{}", u32::from(m).count_ones()))
                .unwrap_or_default();
            let detail = format!("{ip}{prefix}");

            let collision = ifaces
                .iter()
                .find(|o| o.name != iface.name && same_ipv4_network(iface, o));

            match collision {
                None => CheckResult::pass(format!("LAN {}", iface.name), detail),
                Some(other) => CheckResult::fail(
                    format!("LAN {}", iface.name),
                    format!(
                        "Shares subnet with {} — change one router's subnet",
                        other.name
                    ),
                    detail,
                ),
            }
        })
        .collect()
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
