//! Active sharing session — owns all state that exists while VPN sharing is running.

use std::net::Ipv4Addr;
use std::time::Instant;

use crate::app::traffic::TrafficStats;
use crate::error::Result;
use crate::health::HealthStatus;
use crate::system::{read_mtu, DhcpServer, Firewall, IpForwarding, NatPmpServer};

/// IPv4 TCP/IP header overhead used to clamp MSS from MTU in the pf scrub rule.
const IPV4_TCP_HEADER_OVERHEAD: u16 = 40;

/// Floor on the computed MSS so a pathological `read_mtu` reading can't
/// emit a nonsense scrub rule. 216 = 256 (min reasonable v4 MTU) - 40.
const MIN_SAFE_MSS: u16 = 216;

/// The VPN tunnel currently carrying LAN traffic.
///
/// Single source of truth for the upstream's name + MTU. Every consumer
/// (pf nat rule, pf scrub `max-mss`, `ifconfig <lan> mtu`, NAT-PMP bind,
/// health probe, traffic sampler) reads from one of these — no more
/// independent `read_mtu` calls scattered around.
#[derive(Debug, Clone)]
pub struct ActiveUpstream {
    pub name: String,
    pub mtu: u16,
}

impl ActiveUpstream {
    /// Build an `ActiveUpstream` by reading the iface's current MTU.
    pub async fn detect(name: String) -> Result<Self> {
        let mtu = read_mtu(&name).await?;
        Ok(Self { name, mtu })
    }

    /// MSS clamp for IPv4 pf scrub rules. `mtu - 40`, floored.
    pub fn mss_v4(&self) -> u16 {
        self.mtu
            .saturating_sub(IPV4_TCP_HEADER_OVERHEAD)
            .max(MIN_SAFE_MSS)
    }
}

/// Synchronously restore a LAN interface's MTU. Used by Drop where we can't
/// await — relies on `ifconfig` being fast (< 100ms in practice).
fn restore_mtu_sync(iface: &str, mtu: u16) {
    let _ = std::process::Command::new("ifconfig")
        .args([iface, "mtu", &mtu.to_string()])
        .output();
}

/// Represents an active VPN sharing session.
///
/// Created when sharing starts, dropped when sharing stops (or on panic).
/// Owns the firewall and IP forwarding managers, interface info, and service state.
///
/// The `firewall` and `ip_forwarding` fields are `Option` to support the
/// take/restore pattern: async operations take ownership (setting to `None`),
/// then restore when complete. If Drop runs while they're `None`, it skips
/// those cleanup steps (the async task still holds them).
pub struct SharingSession {
    firewall: Option<Firewall>,
    ip_forwarding: Option<IpForwarding>,

    /// The active VPN upstream (name + MTU). Mutated by the route-change
    /// reactor when the user swaps VPN providers/protocols mid-session.
    pub upstream: ActiveUpstream,
    /// LAN interface name (e.g. "en0").
    pub lan_name: String,
    /// LAN gateway IP (e.g. 192.168.2.1).
    pub lan_ip: Ipv4Addr,

    /// Whether the DHCP server is running.
    pub dhcp_active: bool,
    /// DHCP range being served (start, end).
    pub dhcp_range: Option<(String, String)>,
    /// Whether the NAT-PMP server is running.
    pub natpmp_active: bool,
    /// Handle to the running NAT-PMP server (for shutdown signaling).
    natpmp_server: Option<NatPmpServer>,
    /// Original LAN MTU captured before we changed it. Restored on Drop.
    /// `None` means we never modified the MTU (skip restore).
    pub original_mtu: Option<u16>,
    /// Connection health status (updated by periodic checks).
    pub health_status: HealthStatus,
    /// When the VPN was first observed Down (None when healthy).
    /// Used to compute the auto-stop countdown under `WaitWithTimeout`.
    pub degraded_since: Option<Instant>,
    /// Throughput stats for the VPN interface. Populated by the periodic
    /// sampler in `App::poll_async_results`.
    pub traffic: TrafficStats,
}

impl SharingSession {
    /// Create a new sharing session with the given managers and interface info.
    pub fn new(
        firewall: Firewall,
        ip_forwarding: IpForwarding,
        upstream: ActiveUpstream,
        lan_name: String,
        lan_ip: Ipv4Addr,
    ) -> Self {
        Self {
            firewall: Some(firewall),
            ip_forwarding: Some(ip_forwarding),
            upstream,
            lan_name,
            lan_ip,
            dhcp_active: false,
            dhcp_range: None,
            natpmp_active: false,
            natpmp_server: None,
            original_mtu: None,
            health_status: HealthStatus::default(),
            degraded_since: None,
            traffic: TrafficStats::new(),
        }
    }

    /// Take ownership of firewall and IP forwarding for an async operation.
    ///
    /// After this call, Drop will skip cleanup for these resources (they're
    /// owned by the async task). Call `restore_managers` when the task completes.
    pub fn take_managers(&mut self) -> (Firewall, IpForwarding) {
        let firewall = self.firewall.take().unwrap_or_default();
        let ip_forwarding = self.ip_forwarding.take().unwrap_or_default();
        (firewall, ip_forwarding)
    }

    /// Restore ownership of firewall and IP forwarding after an async operation.
    pub fn restore_managers(&mut self, firewall: Firewall, ip_forwarding: IpForwarding) {
        self.firewall = Some(firewall);
        self.ip_forwarding = Some(ip_forwarding);
    }

    /// Check if the firewall manager reports modified state.
    pub fn ip_forwarding_is_modified(&self) -> bool {
        self.ip_forwarding
            .as_ref()
            .is_some_and(|fwd| fwd.is_modified())
    }

    /// Signal the NAT-PMP server to shut down and clear the handle.
    pub fn shutdown_natpmp(&mut self) {
        if let Some(ref server) = self.natpmp_server {
            server.shutdown();
        }
        self.natpmp_server = None;
    }

    /// Set the NAT-PMP server handle after successful startup.
    pub fn set_natpmp_server(&mut self, server: Option<NatPmpServer>) {
        self.natpmp_server = server;
    }
}

impl Drop for SharingSession {
    fn drop(&mut self) {
        // NAT-PMP first (before firewall so pf anchor flush works)
        if self.natpmp_active {
            if let Some(ref server) = self.natpmp_server {
                server.shutdown();
            }
            NatPmpServer::stop_sync();
        }

        // DHCP
        if self.dhcp_active {
            DhcpServer::stop_sync();
        }

        // Firewall (only if we still own it)
        if let Some(ref mut fw) = self.firewall {
            fw.cleanup_sync();
        }

        // IP forwarding (only if we still own it)
        if let Some(ref mut fwd) = self.ip_forwarding {
            fwd.restore_sync();
        }

        // MTU last — cosmetic, can't break cleanup ordering if it fails.
        if let Some(mtu) = self.original_mtu {
            restore_mtu_sync(&self.lan_name, mtu);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mss_v4_subtracts_ipv4_overhead() {
        let u = ActiveUpstream {
            name: "utun10".into(),
            mtu: 1500,
        };
        assert_eq!(u.mss_v4(), 1460);

        let u = ActiveUpstream {
            name: "utun11".into(),
            mtu: 1380,
        };
        assert_eq!(u.mss_v4(), 1340);
    }

    #[test]
    fn mss_v4_clamps_to_floor() {
        // Pathological MTU values shouldn't emit a sub-216 MSS rule.
        let u = ActiveUpstream {
            name: "broken".into(),
            mtu: 0,
        };
        assert_eq!(u.mss_v4(), 216);
    }
}
