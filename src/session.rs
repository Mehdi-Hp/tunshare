//! Active sharing session — owns all state that exists while VPN sharing is running.

use std::net::Ipv4Addr;

use crate::health::HealthStatus;
use crate::system::{DhcpServer, Firewall, IpForwarding, NatPmpServer};

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

    /// VPN interface name (e.g. "utun4").
    pub vpn_name: String,
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
    /// Connection health status (updated by periodic checks).
    pub health_status: HealthStatus,
}

impl SharingSession {
    /// Create a new sharing session with the given managers and interface info.
    pub fn new(
        firewall: Firewall,
        ip_forwarding: IpForwarding,
        vpn_name: String,
        lan_name: String,
        lan_ip: Ipv4Addr,
    ) -> Self {
        Self {
            firewall: Some(firewall),
            ip_forwarding: Some(ip_forwarding),
            vpn_name,
            lan_name,
            lan_ip,
            dhcp_active: false,
            dhcp_range: None,
            natpmp_active: false,
            natpmp_server: None,
            health_status: HealthStatus::default(),
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
    }
}
