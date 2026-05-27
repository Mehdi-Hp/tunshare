//! Async-result handling. Each `AsyncOpResult` variant has a dedicated
//! `on_*` method so the dispatch table in `handle_async_result` stays
//! short and readable.

use std::time::Instant;

use crate::doctor::{CheckStatus, CheckSummary};
use crate::error::Result;
use crate::health::{HealthStatus, VpnDropStrategy};
use crate::system::{Firewall, InterfaceInfo, IpForwarding};

use super::async_ops::{
    AsyncOpResult, DebugInfo, PendingOp, HEALTH_CHECK_INTERVAL, HEALTH_RECHECK_DEGRADED,
};
use super::{App, AppState};

impl App {
    /// Dispatch a completed async result to its handler. The stale-result
    /// guard runs first — except for `Sharing{Started,Stopped}`, which must
    /// always reclaim firewall/ip_forwarding ownership regardless of the
    /// current pending op (otherwise Drop would clean them up twice).
    pub(super) fn handle_async_result(&mut self, result: AsyncOpResult) {
        if !self.result_matches_pending(&result) {
            self.log_info("Discarded stale async result");
            return;
        }

        match result {
            AsyncOpResult::InterfacesDetected { vpn, lan } => self.on_interfaces_detected(vpn, lan),
            AsyncOpResult::DnsDiscovered {
                vpn_servers,
                system_servers,
            } => self.on_dns_discovered(vpn_servers, system_servers),
            AsyncOpResult::SharingStarted {
                result,
                firewall,
                ip_forwarding,
            } => self.on_sharing_started(result, firewall, ip_forwarding),
            AsyncOpResult::DhcpStarted { result } => self.on_dhcp_started(result),
            AsyncOpResult::NatPmpStarted { result, server } => {
                self.on_natpmp_started(result, server)
            }
            AsyncOpResult::SharingStopped {
                result,
                firewall,
                ip_forwarding,
            } => self.on_sharing_stopped(result, firewall, ip_forwarding),
            AsyncOpResult::DebugInfoFetched { info } => self.on_debug_info_fetched(info),
            AsyncOpResult::HealthCheck { status } => self.handle_health_result(status),
            AsyncOpResult::DoctorFinished { results } => self.on_doctor_finished(results),
            AsyncOpResult::DoctorAnchorFlushed { result } => self.on_doctor_anchor_flushed(result),
            AsyncOpResult::DnsmasqInstalled {
                result,
                stderr_tail,
            } => self.on_dnsmasq_installed(result, stderr_tail),
        }
    }

    /// Stale-result guard. `SharingStarted`/`SharingStopped` and `HealthCheck`
    /// are always accepted; everything else must match the pending op.
    fn result_matches_pending(&self, result: &AsyncOpResult) -> bool {
        matches!(
            (result, self.pending_op),
            // These carry firewall/ip_forwarding — always accept.
            (AsyncOpResult::SharingStarted { .. }, _)
                | (AsyncOpResult::SharingStopped { .. }, _)
                // Health checks run outside the pending-op system.
                | (AsyncOpResult::HealthCheck { .. }, _)
                | (AsyncOpResult::InterfacesDetected { .. }, Some(PendingOp::DetectingInterfaces))
                | (AsyncOpResult::DnsDiscovered { .. }, Some(PendingOp::DiscoveringDns))
                | (AsyncOpResult::DhcpStarted { .. }, Some(PendingOp::StartingDhcp))
                | (AsyncOpResult::NatPmpStarted { .. }, Some(PendingOp::StartingNatPmp))
                | (AsyncOpResult::DebugInfoFetched { .. }, Some(PendingOp::FetchingDebugInfo))
                | (AsyncOpResult::DoctorFinished { .. }, Some(PendingOp::RunningDoctor))
                | (
                    AsyncOpResult::DoctorAnchorFlushed { .. },
                    Some(PendingOp::FlushingStaleAnchor)
                )
                | (
                    AsyncOpResult::DnsmasqInstalled { .. },
                    Some(PendingOp::InstallingDnsmasq)
                )
        )
    }

    /// Cancel whatever's pending. The spawned task still runs to completion;
    /// its result gets dropped by the stale guard (except sharing
    /// start/stop, which always restore resource ownership).
    pub(super) fn cancel_pending_op(&mut self) {
        let Some(op) = self.pending_op else {
            return;
        };
        self.log_warning(format!("Cancelled: {}", op.display()));
        self.clear_pending_op();

        match op {
            PendingOp::DetectingInterfaces => self.state = AppState::Menu,
            PendingOp::DiscoveringDns => self.state = AppState::SelectingVpn,
            PendingOp::StartingSharing | PendingOp::StartingDhcp | PendingOp::StartingNatPmp => {
                self.state = AppState::Menu;
            }
            // Stop runs to completion; SharingStopped always restores managers.
            PendingOp::StoppingSharing => {}
            // Dismiss debug; stay where we are.
            PendingOp::FetchingDebugInfo => {}
            PendingOp::RunningDoctor => self.state = AppState::Menu,
            // Stay in Doctor; user can re-run.
            PendingOp::FlushingStaleAnchor => {}
            // brew install runs to completion; result is dropped by the
            // stale guard. Return to Menu so the user isn't stuck on a
            // half-cancelled modal.
            PendingOp::InstallingDnsmasq => self.state = AppState::Menu,
        }
    }

    // ===== Per-result handlers =====

    fn on_interfaces_detected(
        &mut self,
        vpn: Result<Vec<InterfaceInfo>>,
        lan: Result<Vec<InterfaceInfo>>,
    ) {
        self.clear_pending_op();

        match vpn {
            Ok(interfaces) => {
                let count = interfaces.len();
                self.vpn_interfaces = interfaces;
                if count > 0 {
                    self.log_success(format!("Found {} VPN interface(s)", count));
                } else {
                    self.log_warning("No VPN interfaces found. Is your VPN connected?");
                }
            }
            Err(e) => {
                self.log_error(format!("Failed to detect VPN interfaces: {}", e));
                self.vpn_interfaces.clear();
            }
        }

        match lan {
            Ok(interfaces) => {
                let count = interfaces.len();
                self.lan_interfaces = interfaces;
                if count > 0 {
                    self.log_success(format!("Found {} LAN interface(s)", count));
                } else {
                    self.log_warning("No LAN interfaces found");
                }
            }
            Err(e) => {
                self.log_error(format!("Failed to detect LAN interfaces: {}", e));
                self.lan_interfaces.clear();
            }
        }

        if !self.vpn_interfaces.is_empty() && !self.lan_interfaces.is_empty() {
            self.state = AppState::SelectingVpn;
            self.selected_vpn = Some(0);
            self.log_info("Select VPN interface to share from");
        } else {
            // Pre-flight failed: at least one prerequisite is missing. The
            // modal reads `vpn_interfaces` and `lan_interfaces` directly to
            // decide which rows to show.
            self.state = AppState::PreflightBlocked;
        }
    }

    fn on_dns_discovered(
        &mut self,
        vpn_servers: Result<Vec<String>>,
        system_servers: Result<Vec<String>>,
    ) {
        self.clear_pending_op();

        match vpn_servers {
            Ok(servers) => {
                if servers.is_empty() {
                    self.log_warning("No VPN DNS servers found");
                } else {
                    self.log_success(format!("VPN DNS: {}", servers.join(", ")));
                }
                self.dns.vpn_servers = servers;
            }
            Err(e) => {
                self.log_warning(format!("VPN DNS discovery failed: {}", e));
                self.dns.vpn_servers.clear();
            }
        }

        match system_servers {
            Ok(servers) => {
                if !servers.is_empty() {
                    self.log_info(format!("System DNS: {}", servers.join(", ")));
                }
                self.dns.system_servers = servers;
            }
            Err(_) => self.dns.system_servers.clear(),
        }

        self.state = AppState::SelectingLan;
        self.selected_lan = if self.lan_interfaces.is_empty() {
            None
        } else {
            Some(0)
        };
        self.log_info("Select LAN interface to share to");
    }

    fn on_sharing_started(
        &mut self,
        result: Result<Option<u16>>,
        firewall: Firewall,
        ip_forwarding: IpForwarding,
    ) {
        // ALWAYS restore managers to prevent Drop cleanup, even if cancelled.
        if let Some(ref mut session) = self.session {
            session.restore_managers(firewall, ip_forwarding);
        }

        // Cancelled mid-flight: don't proceed with the rest of the startup chain.
        if self.pending_op != Some(PendingOp::StartingSharing) {
            self.log_info("Sharing result arrived after cancel (resources restored)");
            return;
        }

        match result {
            Ok(original_mtu) => {
                if let Some(ref mut session) = self.session {
                    session.original_mtu = original_mtu;
                }
                if let Some(orig) = original_mtu {
                    self.log_info(format!("LAN MTU applied (was <{orig}>, restored on stop)"));
                }
                let lan_ip_display = self
                    .session
                    .as_ref()
                    .map(|s| s.lan_ip.to_string())
                    .unwrap_or_else(|| "unknown".into());
                self.log_success(format!("VPN sharing active! Gateway: {}", lan_ip_display));

                if self.dhcp_enabled && self.dnsmasq_installed {
                    if let Some(session) = self.session.as_ref() {
                        let lan_name = session.lan_name.clone();
                        let lan_ip = session.lan_ip;
                        self.start_dhcp_async(lan_name, lan_ip);
                        return;
                    }
                } else if !self.dhcp_enabled {
                    self.log_info("DHCP disabled by user preference");
                    self.log_manual_router_config();
                } else {
                    self.log_info("DHCP disabled (dnsmasq not installed)");
                    self.log_manual_router_config();
                }

                if self.maybe_start_natpmp() {
                    return;
                }
                self.finish_startup();
            }
            Err(e) => {
                self.log_error(format!("Failed to start sharing: {}", e));
                self.clear_pending_op();
                self.state = AppState::Menu;
                self.session = None;
            }
        }
    }

    fn on_dhcp_started(&mut self, result: Result<()>) {
        match result {
            Ok(()) => {
                let log_msg = if let Some(ref mut session) = self.session {
                    session.dhcp_active = true;
                    match &session.dhcp_range {
                        Some((start, end)) => format!("DHCP server active ({}-{})", start, end),
                        None => "DHCP server active".to_string(),
                    }
                } else {
                    "DHCP server active".to_string()
                };
                self.log_success(log_msg);
                self.log_info("Router can now use DHCP on WAN interface");
            }
            Err(e) => {
                self.log_warning(format!("DHCP server failed: {}", e));
                self.log_manual_router_config();
            }
        }

        if self.maybe_start_natpmp() {
            return;
        }
        self.finish_startup();
    }

    fn on_natpmp_started(
        &mut self,
        result: Result<()>,
        server: Option<crate::system::NatPmpServer>,
    ) {
        match result {
            Ok(()) => {
                if let Some(ref mut session) = self.session {
                    session.natpmp_active = true;
                    session.set_natpmp_server(server);
                }
                self.log_success("NAT-PMP server active");
            }
            Err(e) => self.log_warning(format!("NAT-PMP server failed: {}", e)),
        }
        self.finish_startup();
    }

    fn on_sharing_stopped(
        &mut self,
        result: Result<()>,
        firewall: Firewall,
        ip_forwarding: IpForwarding,
    ) {
        // Restore managers before dropping session (prevents double cleanup).
        if let Some(ref mut session) = self.session {
            session.restore_managers(firewall, ip_forwarding);
        }
        self.clear_pending_op();

        match result {
            Ok(()) => self.log_success("VPN sharing stopped"),
            Err(e) => self.log_error(format!("Cleanup warning: {}", e)),
        }

        self.session = None;
        self.next_health_check = None;
        self.state = AppState::Menu;
        self.selected_menu_item = 0;
        self.show_debug = false;
        self.debug_info = None;
    }

    fn on_debug_info_fetched(&mut self, info: Result<DebugInfo>) {
        self.clear_pending_op();
        match info {
            Ok(debug_info) => self.debug_info = Some(debug_info),
            Err(e) => {
                self.log_warning(format!("Failed to fetch debug info: {}", e));
                self.debug_info = None;
            }
        }
    }

    fn on_doctor_finished(&mut self, results: Vec<crate::doctor::CheckResult>) {
        self.clear_pending_op();
        let summary = CheckSummary::from_results(&results);
        self.log_info(format!(
            "Doctor: {} pass · {} warn · {} fail",
            summary.pass, summary.warn, summary.fail
        ));
        if self.doctor.selected >= results.len() {
            self.doctor.selected = 0;
        }
        self.doctor.results = results;
    }

    fn on_dnsmasq_installed(&mut self, result: Result<()>, stderr_tail: String) {
        self.clear_pending_op();
        match result {
            Ok(()) => {
                // Re-detect — `brew install` succeeding doesn't guarantee
                // dnsmasq actually landed in a path we look at.
                let now_installed = crate::system::DhcpServer::is_dnsmasq_installed();
                self.dnsmasq_installed = now_installed;
                if now_installed {
                    self.log_success("dnsmasq installed");
                    // User triggered the install from the DHCP menu item —
                    // flip it on so they don't need a second Enter.
                    if !self.dhcp_enabled {
                        self.dhcp_enabled = true;
                        self.log_info("DHCP server enabled");
                    }
                    self.save_preferences();
                } else {
                    self.log_error(
                        "brew install dnsmasq reported success but binary not found in expected paths",
                    );
                }
            }
            Err(e) => {
                self.log_error(format!("brew install dnsmasq failed: {e}"));
                for line in stderr_tail.lines() {
                    self.log_error(format!("  {line}"));
                }
            }
        }
        self.state = AppState::Menu;
    }

    fn on_doctor_anchor_flushed(&mut self, result: Result<()>) {
        self.clear_pending_op();
        match result {
            Ok(()) => {
                self.log_success("Flushed stale 'vpn_share' pf anchor");
                // Re-run checks so the user sees the resolution immediately.
                self.run_doctor_async();
            }
            Err(e) => self.log_error(format!("Failed to flush pf anchor: {e}")),
        }
    }

    // ===== Health checks =====

    /// Apply a health-check result: log transitions, track Down windows,
    /// reschedule the next check, and auto-stop if the wait window has elapsed.
    fn handle_health_result(&mut self, status: HealthStatus) {
        let Some(session) = self.session.as_mut() else {
            return;
        };

        let now = Instant::now();
        let was_down = matches!(session.health_status, HealthStatus::Down(_));
        let now_down = matches!(status, HealthStatus::Down(_));
        let transitioned = status != session.health_status;

        if now_down && !was_down {
            session.degraded_since = Some(now);
        } else if !now_down {
            session.degraded_since = None;
        }

        let degraded_since = session.degraded_since;
        session.health_status = status.clone();

        // Log only on transitions — would otherwise spam every recheck while Down.
        if transitioned {
            match &status {
                HealthStatus::Healthy => {
                    if was_down {
                        self.log_success("VPN recovered — sharing continues");
                    } else {
                        self.log_success("Connection recovered");
                    }
                }
                HealthStatus::Degraded(reason) => {
                    self.log_warning(format!("Connection degraded: {}", reason));
                }
                HealthStatus::Down(reason) => {
                    self.log_warning(format!("VPN down: {}", reason));
                    match self.vpn_drop_strategy {
                        VpnDropStrategy::WaitWithTimeout { timeout_secs } => self.log_info(
                            format!("Auto-stopping in {timeout_secs}s if VPN does not recover"),
                        ),
                        VpnDropStrategy::AutoStop => {
                            self.log_warning("Auto-stop strategy: tearing down now")
                        }
                        VpnDropStrategy::Ignore => {
                            self.log_info("Ignore strategy: leaving sharing up")
                        }
                    }
                }
            }
        }

        // Only Down triggers the drop strategy; Degraded is recoverable.
        let should_stop = if now_down {
            match self.vpn_drop_strategy.wait_duration() {
                Some(wait) => {
                    let since = degraded_since.unwrap_or(now);
                    now.duration_since(since) >= wait
                }
                None => false,
            }
        } else {
            false
        };

        if should_stop {
            self.log_warning("VPN-drop timeout exceeded — auto-stopping");
            self.stop_sharing_async();
        } else if now_down {
            self.next_health_check = Some(now + HEALTH_RECHECK_DEGRADED);
        } else {
            self.next_health_check = Some(now + HEALTH_CHECK_INTERVAL);
        }
    }

    // ===== Small shared helpers =====

    /// Three startup branches all log the same "DHCP isn't running, you'll
    /// need to configure your router by hand" hint. Pulled out so they
    /// stay in lockstep.
    fn log_manual_router_config(&mut self) {
        let eff = self.dns.effective();
        if eff.is_empty() {
            self.log_info("Router needs manual IP configuration");
        } else {
            self.log_info(format!(
                "Configure router manually - DNS: {}",
                eff.join(", ")
            ));
        }
    }

    /// True if the doctor's most recent run flagged a stale pf anchor.
    /// Drives the `[c]` hint in the help bar and the `c` key in input.
    pub fn doctor_has_stale_anchor(&self) -> bool {
        self.doctor.results.iter().any(|r| {
            matches!(r.status, CheckStatus::Fail { .. }) && r.name.contains("pf anchor clean")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn make_iface(name: &str) -> InterfaceInfo {
        InterfaceInfo {
            name: name.to_string(),
            ipv4_address: Some(Ipv4Addr::new(192, 168, 1, 1)),
            ipv4_netmask: Some(Ipv4Addr::new(255, 255, 255, 0)),
            description: None,
            is_up: true,
        }
    }

    #[test]
    fn pre_flight_blocks_when_both_lists_empty() {
        let mut app = App::new();
        app.on_interfaces_detected(Ok(vec![]), Ok(vec![]));
        assert_eq!(app.state, AppState::PreflightBlocked);
    }

    #[test]
    fn pre_flight_blocks_when_only_vpn_missing() {
        let mut app = App::new();
        app.on_interfaces_detected(Ok(vec![]), Ok(vec![make_iface("en0")]));
        assert_eq!(app.state, AppState::PreflightBlocked);
    }

    #[test]
    fn pre_flight_blocks_when_only_lan_missing() {
        let mut app = App::new();
        app.on_interfaces_detected(Ok(vec![make_iface("utun0")]), Ok(vec![]));
        assert_eq!(app.state, AppState::PreflightBlocked);
    }

    #[test]
    fn pre_flight_passes_when_both_present() {
        let mut app = App::new();
        app.on_interfaces_detected(Ok(vec![make_iface("utun0")]), Ok(vec![make_iface("en0")]));
        assert_eq!(app.state, AppState::SelectingVpn);
        assert_eq!(app.selected_vpn, Some(0));
    }
}
