//! Active sharing session — owns all state that exists while VPN sharing is running.

use std::net::Ipv4Addr;
use std::time::Instant;

use crate::app::traffic::TrafficStats;
use crate::config::LanMtu;
use crate::error::Result;
use crate::health::HealthStatus;
use crate::system::{
    probe_path_mtu, read_mtu, DhcpServer, DnsServer, Firewall, IpForwarding, NatPmpServer,
    WanUplink, CONSERVATIVE_MTU,
};

/// IPv4 TCP/IP header overhead used to clamp MSS from MTU in the pf scrub rule.
const IPV4_TCP_HEADER_OVERHEAD: u16 = 40;

/// Floor on the computed MSS so a pathological `read_mtu` reading can't
/// emit a nonsense scrub rule. 216 = 256 (min reasonable v4 MTU) - 40.
const MIN_SAFE_MSS: u16 = 216;

/// The VPN tunnel currently carrying LAN traffic.
///
/// Single source of truth for the upstream's name + MTU. Every consumer
/// (pf nat rule, pf scrub `max-mss`, NAT-PMP bind, health probe, traffic
/// sampler) reads from one of these — no more independent `read_mtu` calls
/// scattered around.
#[derive(Debug, Clone)]
pub struct ActiveUpstream {
    pub name: String,
    /// Raw MTU the utun reports. On encapsulating tunnels (OpenVPN-UDP) this
    /// over-reports what the path can carry — that's the bug this whole module
    /// works around — so it's kept only for display/debug, never the clamp.
    pub link_mtu: u16,
    /// Effective MTU that drives the pf scrub clamp: the probed path MTU under
    /// `Auto`, the user's value under `Fixed`, or the conservative cap when a
    /// probe is inconclusive. Always ≤ `link_mtu` in practice.
    pub effective_mtu: u16,
}

impl ActiveUpstream {
    /// Build an `ActiveUpstream`: read the link MTU, then resolve the effective
    /// (clamp-driving) MTU per the user's policy. Under `Auto` this runs the
    /// active path-MTU probe, which never fails hard — it degrades to a cap.
    pub async fn detect(name: String, policy: LanMtu) -> Result<Self> {
        let link_mtu = read_mtu(&name).await?;
        let effective_mtu = Self::resolve_effective(&name, link_mtu, policy).await;
        Ok(Self {
            name,
            link_mtu,
            effective_mtu,
        })
    }

    /// Resolve the effective MTU that the MSS clamp derives from. `Auto`
    /// measures the real path MTU and, when the probe is inconclusive (ICMP
    /// blocked, errors, budget spent), falls back to `min(link_mtu,
    /// CONSERVATIVE_MTU)` — never the inflated `link_mtu`. `Fixed(n)` trusts
    /// the user's value outright and skips the probe.
    async fn resolve_effective(name: &str, link_mtu: u16, policy: LanMtu) -> u16 {
        match policy {
            LanMtu::Auto => probe_path_mtu(name, link_mtu)
                .await
                .unwrap_or_else(|| link_mtu.min(CONSERVATIVE_MTU)),
            LanMtu::Fixed(n) => n,
        }
    }

    /// MSS clamp for IPv4 pf scrub rules. `effective_mtu - 40`, floored.
    pub fn mss_v4(&self) -> u16 {
        self.effective_mtu
            .saturating_sub(IPV4_TCP_HEADER_OVERHEAD)
            .max(MIN_SAFE_MSS)
    }
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
    /// WAN uplink for allowlisted destinations. Required when the allowlist is on.
    pub wan: Option<WanUplink>,
    /// In-process LAN DNS server (always running while sharing).
    dns_server: Option<DnsServer>,

    /// Whether the DHCP server is running.
    pub dhcp_active: bool,
    /// DHCP range being served (start, end).
    pub dhcp_range: Option<(String, String)>,
    /// Whether the NAT-PMP server is running.
    pub natpmp_active: bool,
    /// Handle to the running NAT-PMP server (for shutdown signaling).
    natpmp_server: Option<NatPmpServer>,
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
            wan: None,
            dns_server: None,
            dhcp_active: false,
            dhcp_range: None,
            natpmp_active: false,
            natpmp_server: None,
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

    pub fn set_dns_server(&mut self, server: Option<DnsServer>) {
        if let Some(ref existing) = self.dns_server {
            existing.shutdown();
        }
        self.dns_server = server;
    }

    pub fn dns_server(&self) -> Option<&DnsServer> {
        self.dns_server.as_ref()
    }

    pub fn shutdown_dns(&mut self) {
        if let Some(ref server) = self.dns_server {
            server.shutdown();
        }
        self.dns_server = None;
    }
}

impl Drop for SharingSession {
    fn drop(&mut self) {
        // Resolver first so :53 is free before pf restore.
        if let Some(ref server) = self.dns_server {
            server.shutdown();
        }

        // NAT-PMP next (before firewall so pf anchor flush works)
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upstream(effective_mtu: u16) -> ActiveUpstream {
        ActiveUpstream {
            name: "utun10".into(),
            link_mtu: 1500,
            effective_mtu,
        }
    }

    #[test]
    fn mss_v4_subtracts_ipv4_overhead_from_effective_mtu() {
        // The clamp tracks the effective MTU, not the (possibly inflated) link.
        assert_eq!(upstream(1500).mss_v4(), 1460);
        assert_eq!(upstream(1440).mss_v4(), 1400);
        assert_eq!(upstream(1380).mss_v4(), 1340);
    }

    #[test]
    fn mss_v4_clamps_to_floor() {
        // Pathological MTU values shouldn't emit a sub-216 MSS rule.
        assert_eq!(upstream(0).mss_v4(), 216);
    }

    #[tokio::test]
    async fn fixed_policy_uses_the_value_verbatim_without_probing() {
        // `Fixed` must never touch the network — it trusts the user's value.
        let mtu = ActiveUpstream::resolve_effective("utun10", 1500, LanMtu::Fixed(1440)).await;
        assert_eq!(mtu, 1440);
    }
}
