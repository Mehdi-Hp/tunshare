//! Connection health monitoring.
//!
//! Periodic checks that verify the VPN sharing setup is still working:
//! VPN interface up, IP forwarding enabled, pf contract still loaded.

use std::net::Ipv4Addr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::process::Command;

use crate::system::{BypassConfig, Firewall};

/// Overall health status of the active sharing session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum HealthStatus {
    /// Everything is working normally.
    #[default]
    Healthy,
    /// Something is degraded but traffic may still flow.
    Degraded(String),
    /// VPN interface is down — traffic is not flowing.
    Down(String),
}

/// What to do when the VPN interface drops mid-session.
///
/// pf NAT rules egress on the VPN interface, so when utun goes down the
/// kernel drops packets — they don't fail-open to the physical interface.
/// That means the wait window has no leak risk; it's purely a UX choice
/// between resilience to transient drops and aggressive teardown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum VpnDropStrategy {
    /// Tear down `timeout_secs` after a VPN drop is first detected,
    /// giving brief reconnects (rehandshake, IKE rekey, sleep/wake) a chance
    /// to ride through without restarting the session.
    WaitWithTimeout { timeout_secs: u64 },
    /// Tear down immediately on first detected drop.
    AutoStop,
    /// Cosmetic-only: log the drop but keep everything running.
    Ignore,
}

impl Default for VpnDropStrategy {
    fn default() -> Self {
        Self::WaitWithTimeout { timeout_secs: 15 }
    }
}

impl VpnDropStrategy {
    /// How long to wait before auto-stopping. `None` means never (Ignore).
    pub fn wait_duration(self) -> Option<Duration> {
        match self {
            Self::WaitWithTimeout { timeout_secs } => Some(Duration::from_secs(timeout_secs)),
            Self::AutoStop => Some(Duration::ZERO),
            Self::Ignore => None,
        }
    }
}

/// Fields needed to re-merge MAIN hooks / reload `com.tunshare` if health
/// finds the bypass contract missing. Heal does not take Firewall ownership.
#[derive(Debug, Clone)]
pub struct HealPlan {
    pub vpn_if: String,
    pub lan_if: String,
    pub lan_ip: Ipv4Addr,
    pub mss: u16,
    pub bypass: Option<BypassConfig>,
    pub bypass_on: bool,
}

/// Run health checks against the active sharing session.
///
/// Checks (in order of severity):
/// 1. VPN interface is still UP (critical — if down, all traffic fails)
/// 2. pf contract (MAIN hooks; WAN NAT + route-to when bypass is on)
/// 3. IP forwarding is still enabled (warning — can be re-enabled)
///
/// `healed` is true only
/// when restore ran and the contract came back. Heal never flushes
/// `<tunshare_bypass>`.
pub async fn check_health_with_heal(
    vpn_name: &str,
    heal: Option<&HealPlan>,
) -> (HealthStatus, bool) {
    if !is_interface_up(vpn_name).await {
        return (
            HealthStatus::Down(format!("VPN interface {vpn_name} is no longer up")),
            false,
        );
    }

    let mut healed = false;
    if let Some(plan) = heal {
        match inspect_and_maybe_heal(plan).await {
            Ok(true) => healed = true,
            Ok(false) => {}
            Err(reason) => {
                return (HealthStatus::Degraded(reason), false);
            }
        }
    }

    if !is_ip_forwarding_enabled().await {
        return (
            HealthStatus::Degraded("IP forwarding was disabled externally".into()),
            healed,
        );
    }

    (HealthStatus::Healthy, healed)
}

async fn inspect_and_maybe_heal(plan: &HealPlan) -> Result<bool, String> {
    let before = Firewall::inspect_live()
        .await
        .map_err(|error| error.to_string())?;
    if contract_holds(&before, plan.bypass_on) {
        return Ok(false);
    }
    Firewall::restore_contract(
        &plan.vpn_if,
        &plan.lan_if,
        plan.lan_ip,
        plan.mss,
        plan.bypass.as_ref(),
    )
    .await
    .map_err(|error| format!("pf heal failed: {error}"))?;
    let after = Firewall::inspect_live()
        .await
        .map_err(|error| error.to_string())?;
    if contract_holds(&after, plan.bypass_on) {
        Ok(true)
    } else {
        Err(after
            .miss_message(plan.bypass_on)
            .unwrap_or("pf contract still missing after heal")
            .to_string())
    }
}

fn contract_holds(contract: &crate::system::PfContract, bypass_on: bool) -> bool {
    if bypass_on {
        contract.bypass_ok()
    } else {
        contract.sharing_ok()
    }
}

/// Check whether a network interface has the UP flag.
async fn is_interface_up(interface: &str) -> bool {
    let Ok(output) = Command::new("ifconfig").arg(interface).output().await else {
        // Can't run ifconfig — assume OK rather than false-alarming
        return true;
    };

    if !output.status.success() {
        // Interface doesn't exist anymore
        return false;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // The flags line looks like: "utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1400"
    stdout.contains("UP")
}

/// Check whether IP forwarding is enabled via sysctl.
async fn is_ip_forwarding_enabled() -> bool {
    let Ok(output) = Command::new("sysctl")
        .arg("-n")
        .arg("net.inet.ip.forwarding")
        .output()
        .await
    else {
        return true; // Can't check — assume OK
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.trim() == "1"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::Firewall;
    use std::net::Ipv4Addr;

    #[test]
    fn contract_holds_needs_hooks_and_route_to() {
        let bypass = BypassConfig {
            wan_if: "en0".into(),
            wan_gw: Ipv4Addr::new(192, 168, 1, 1),
        };
        let body = Firewall::generate_rules(
            "utun4",
            "en8",
            Ipv4Addr::new(192, 168, 2, 1),
            1400,
            Some(&bypass),
        );
        let hooked = Firewall::contract_from_text(&Firewall::generate_main_hooks(), &body);
        assert!(contract_holds(&hooked, true));
        let unhooked = Firewall::contract_from_text("", &body);
        assert!(!contract_holds(&unhooked, true));
        assert!(unhooked.has_route_to);
    }

    #[test]
    fn restore_contract_is_not_cleanup() {
        // Heal reloads body + MAIN hooks. table_flush lives only on stop
        // and allowlist-off reload — grep-enforced by this module split.
        let src = include_str!("system/firewall.rs");
        assert!(src.contains("pub async fn restore_contract"));
        let restore = src
            .split("pub async fn restore_contract")
            .nth(1)
            .and_then(|rest| rest.split("pub async fn get_current_rules").next())
            .expect("restore_contract body");
        assert!(
            !restore.contains("table_flush"),
            "heal must not flush <tunshare_bypass>"
        );
    }
}
