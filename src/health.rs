//! Connection health monitoring.
//!
//! Periodic checks that verify the VPN sharing setup is still working:
//! VPN interface up, IP forwarding enabled.

use tokio::process::Command;

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

/// Run health checks against the active sharing session.
///
/// Checks (in order of severity):
/// 1. VPN interface is still UP (critical — if down, all traffic fails)
/// 2. IP forwarding is still enabled (warning — can be re-enabled)
pub async fn check_health(vpn_name: &str) -> HealthStatus {
    // Check VPN interface
    if !is_interface_up(vpn_name).await {
        return HealthStatus::Down(format!("VPN interface {} is no longer up", vpn_name));
    }

    // Check IP forwarding
    if !is_ip_forwarding_enabled().await {
        return HealthStatus::Degraded("IP forwarding was disabled externally".to_string());
    }

    HealthStatus::Healthy
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
