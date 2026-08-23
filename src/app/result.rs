//! Async-result handling. Each `AsyncOpResult` variant has a dedicated
//! `on_*` method so the dispatch table in `handle_async_result` stays
//! short and readable.

use std::time::Instant;

use crate::doctor::{CheckStatus, CheckSummary};
use crate::error::Result;
use crate::health::{HealthStatus, VpnDropStrategy};
use crate::system::{DnsServer, Firewall, InterfaceInfo, IpForwarding, NatPmpServer, WanUplink};

use super::async_ops::{
    AsyncOpResult, DebugInfo, PendingOp, HEALTH_CHECK_INTERVAL, HEALTH_RECHECK_DEGRADED,
};
use super::traffic::SAMPLE_INTERVAL;
use super::{App, AppState};
use crate::system::InterfaceBytes;

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
                wan,
                firewall,
                ip_forwarding,
            } => self.on_sharing_started(result, wan, firewall, ip_forwarding),
            AsyncOpResult::ResolverStarted {
                result,
                block_count,
                allow_count,
                block_fetched,
                allow_fetched,
            } => self.on_resolver_started(
                result,
                block_count,
                allow_count,
                block_fetched,
                allow_fetched,
            ),
            AsyncOpResult::ListsRefreshed {
                block,
                allow,
                apply,
            } => self.on_lists_refreshed(block, allow, apply),
            AsyncOpResult::FirewallReloaded {
                result,
                firewall,
                allowlist_on,
            } => self.on_firewall_reloaded(result, firewall, allowlist_on),
            AsyncOpResult::WanDetected { result } => self.on_wan_detected(result),
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
            AsyncOpResult::HealthCheck {
                status,
                default_iface,
            } => self.handle_health_result(status, default_iface),
            AsyncOpResult::TrafficSample { result } => self.handle_traffic_sample(result),
            AsyncOpResult::DoctorFinished { results } => self.on_doctor_finished(results),
            AsyncOpResult::DoctorAnchorFlushed { result } => self.on_doctor_anchor_flushed(result),
            AsyncOpResult::DnsmasqInstalled {
                result,
                stderr_tail,
            } => self.on_dnsmasq_installed(result, stderr_tail),
            AsyncOpResult::UpstreamReloaded {
                result,
                firewall,
                natpmp_server,
            } => self.on_upstream_reloaded(result, firewall, natpmp_server),
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
                // Traffic samples run outside the pending-op system too.
                | (AsyncOpResult::TrafficSample { .. }, _)
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
                | (
                    AsyncOpResult::ResolverStarted { .. },
                    Some(PendingOp::StartingResolver)
                )
                | (
                    AsyncOpResult::ListsRefreshed { .. },
                    Some(PendingOp::RefreshingLists)
                )
                | (
                    AsyncOpResult::FirewallReloaded { .. },
                    Some(PendingOp::ReloadingFirewall)
                )
                | (
                    AsyncOpResult::WanDetected { .. },
                    Some(PendingOp::DetectingWan)
                )
                // Reload also carries the firewall — always accept.
                | (AsyncOpResult::UpstreamReloaded { .. }, _)
                | (AsyncOpResult::FirewallReloaded { .. }, _)
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
            PendingOp::StartingSharing
            | PendingOp::StartingDhcp
            | PendingOp::StartingNatPmp
            | PendingOp::StartingResolver => {
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
            // Reload runs to completion; result restores firewall ownership.
            PendingOp::ReloadingUpstream | PendingOp::ReloadingFirewall => {}
            PendingOp::RefreshingLists | PendingOp::DetectingWan => {}
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
        result: Result<crate::session::ActiveUpstream>,
        wan: Option<WanUplink>,
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
            Ok(upstream) => {
                // Replace the placeholder (MTU=0) with the resolved upstream.
                // All downstream consumers (reactor, future rule reloads) now
                // have real link + effective MTUs to work with.
                let (link, eff, mss) =
                    (upstream.link_mtu, upstream.effective_mtu, upstream.mss_v4());
                if let Some(ref mut session) = self.session {
                    session.upstream = upstream;
                    session.wan = wan;
                }
                if let Some(wan) = self.session.as_ref().and_then(|s| s.wan.as_ref()) {
                    self.log_info(format!("WAN uplink <{}> via <{}>", wan.iface, wan.gateway));
                }
                if eff < link {
                    self.log_info(format!(
                        "Tunnel path MTU <{eff}> (link <{link}>) → clamping MSS to <{mss}>"
                    ));
                } else {
                    self.log_info(format!("Tunnel MTU <{eff}> → clamping MSS to <{mss}>"));
                }
                let lan_ip_display = self
                    .session
                    .as_ref()
                    .map(|s| s.lan_ip.to_string())
                    .unwrap_or_else(|| "unknown".into());
                self.log_success(format!("VPN sharing active! Gateway: {}", lan_ip_display));
                self.maybe_start_resolver();
            }
            Err(e) => {
                self.log_error(format!("Failed to start sharing: {}", e));
                self.clear_pending_op();
                self.state = AppState::Menu;
                self.session = None;
            }
        }
    }

    fn on_resolver_started(
        &mut self,
        result: Result<DnsServer>,
        block_count: usize,
        allow_count: usize,
        block_fetched: Option<std::time::SystemTime>,
        allow_fetched: Option<std::time::SystemTime>,
    ) {
        self.lists_ui.block_count = block_count;
        self.lists_ui.allow_count = allow_count;
        self.lists_ui.block_fetched = block_fetched;
        self.lists_ui.allow_fetched = allow_fetched;

        match result {
            Ok(server) => {
                if let Some(ref mut session) = self.session {
                    session.set_dns_server(Some(server));
                }
                self.log_success(format!(
                    "LAN resolver on :53 (block {block_count}, allow {allow_count})"
                ));
                self.continue_after_resolver();
            }
            Err(error) => {
                self.log_error(format!("DNS resolver failed: {error}"));
                self.clear_pending_op();
                self.state = AppState::Menu;
                self.session = None;
            }
        }
    }

    fn continue_after_resolver(&mut self) {
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

    fn on_lists_refreshed(
        &mut self,
        block: crate::system::LoadedList,
        allow: crate::system::LoadedList,
        apply: bool,
    ) {
        self.clear_pending_op();
        for error in block.errors.iter().chain(allow.errors.iter()) {
            self.log_warning(format!("List fetch: {error}"));
        }
        if block.used_stale || allow.used_stale {
            self.log_warning("Using stale cached lists");
        }
        self.lists_ui.block_count = block.set.len();
        self.lists_ui.allow_count = allow.set.len();
        self.lists_ui.block_fetched = block.last_fetch;
        self.lists_ui.allow_fetched = allow.last_fetch;
        self.log_info(format!(
            "Lists: block {} · allow {}",
            block.set.len(),
            allow.set.len()
        ));
        if apply {
            self.push_lists_to_resolver(Some(&block.set), Some(&allow.set));
        }
    }

    fn on_firewall_reloaded(&mut self, result: Result<()>, firewall: Firewall, allowlist_on: bool) {
        if let Some(ref mut session) = self.session {
            let (_dummy, ip_forwarding) = session.take_managers();
            session.restore_managers(firewall, ip_forwarding);
        }
        self.clear_pending_op();
        match result {
            Ok(()) => {
                if allowlist_on {
                    let wan_ip = self
                        .session
                        .as_ref()
                        .and_then(|s| s.wan.as_ref().map(|w| w.ip));
                    if let Some(wan_ip) = wan_ip {
                        if let Some(server) = self.session.as_ref().and_then(|s| s.dns_server()) {
                            if let Err(error) = server.attach_wan(wan_ip) {
                                self.log_error(format!("WAN DNS attach failed: {error}"));
                                self.lists.allow.enabled = false;
                                self.save_preferences();
                                return;
                            }
                        }
                    }
                    self.lists.allow.enabled = true;
                    self.save_preferences();
                    self.push_lists_to_resolver(None, None);
                    self.log_info("Allowlist on");
                } else {
                    self.log_info("Firewall rules reloaded without WAN bypass");
                    self.push_lists_to_resolver(None, None);
                }
            }
            Err(error) => {
                self.log_error(format!("Firewall reload failed: {error}"));
                self.lists.allow.enabled = false;
                self.save_preferences();
            }
        }
    }

    fn on_wan_detected(&mut self, result: Result<Option<WanUplink>>) {
        self.clear_pending_op();
        match result {
            Ok(Some(wan)) => {
                self.log_info(format!("WAN uplink <{}> via <{}>", wan.iface, wan.gateway));
                if let Some(ref mut session) = self.session {
                    session.wan = Some(wan.clone());
                }
                self.reload_firewall_for_bypass_async(wan);
            }
            Ok(None) => {
                self.log_error(
                    "No WAN uplink found — allowlist needs an ifscoped default besides LAN/VPN",
                );
            }
            Err(error) => {
                self.log_error(format!("WAN detect failed: {error}"));
            }
        }
    }

    pub(super) fn push_lists_to_resolver(
        &self,
        block: Option<&crate::system::DomainSet>,
        allow: Option<&crate::system::DomainSet>,
    ) {
        let Some(session) = self.session.as_ref() else {
            return;
        };
        let Some(server) = session.dns_server() else {
            return;
        };
        let lists = server.lists();
        let block_enabled = self.lists.block.enabled;
        let allow_enabled = self.lists.allow.enabled;
        let block = block.cloned();
        let allow = allow.cloned();
        tokio::spawn(async move {
            let mut current = lists.write().await;
            if let Some(set) = block {
                current.block = set;
            }
            if let Some(set) = allow {
                current.allow = set;
            }
            current.block_enabled = block_enabled;
            current.allow_enabled = allow_enabled;
        });
    }

    /// Restore the firewall + NAT-PMP handle handed back by
    /// `reload_upstream_async`, swap in the new upstream, and log the
    /// transition. Errors leave the previous upstream in place — the next
    /// health probe will retry on the next swap event.
    fn on_upstream_reloaded(
        &mut self,
        result: Result<crate::session::ActiveUpstream>,
        firewall: Firewall,
        natpmp_server: Option<NatPmpServer>,
    ) {
        if let Some(ref mut session) = self.session {
            // Replace the placeholder Firewall::default() the dispatcher
            // stashed with the real one that just loaded the new rules.
            let (_dummy_fw, ip_forwarding) = session.take_managers();
            session.restore_managers(firewall, ip_forwarding);
            session.set_natpmp_server(natpmp_server);
        }
        self.clear_pending_op();

        match result {
            Ok(upstream) => {
                let old_name = self
                    .session
                    .as_ref()
                    .map(|s| s.upstream.name.clone())
                    .unwrap_or_default();
                self.log_success(format!(
                    "Reloaded rules: <{}> → <{}> (MTU <{}>, MSS <{}>)",
                    old_name,
                    upstream.name,
                    upstream.effective_mtu,
                    upstream.mss_v4()
                ));
                if let Some(ref mut session) = self.session {
                    session.upstream = upstream;
                    // Recovery from a swap counts as Healthy — the prior
                    // tick may have marked us Degraded/Down on the dead
                    // utun; the new probe will confirm.
                    session.health_status = HealthStatus::Healthy;
                    session.degraded_since = None;
                }
            }
            Err(e) => {
                self.log_error(format!("Upstream reload failed: {}", e));
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
        self.next_traffic_sample = None;
        self.dns.vpn_servers.clear();
        self.dns.system_servers.clear();
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
    fn handle_health_result(&mut self, status: HealthStatus, default_iface: Option<String>) {
        // Detect VPN-swap before mutating health state. If the default
        // route now points at a *different* utun than our session is
        // bound to, the user switched providers/protocols — kick off a
        // reload instead of letting the existing utun's Down path fire.
        // Anything non-`utun*` (or `None`) means the default route fell
        // off VPN entirely; that's the existing VPN-down case.
        if let Some(session) = self.session.as_ref() {
            if let Some(new_iface) = default_iface.as_deref() {
                if new_iface != session.upstream.name && new_iface.starts_with("utun") {
                    self.log_info(format!(
                        "Default route moved to <{new_iface}> (was <{}>) — reloading rules",
                        session.upstream.name
                    ));
                    self.reload_upstream_async(new_iface.to_string());
                    // Skip the rest of the health bookkeeping for this
                    // tick: the next probe (after the reload) will see
                    // the new iface and report cleanly.
                    return;
                }
            }
        }

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

    /// Fold a fresh `(ibytes, obytes)` sample into the session's stats.
    /// Errors are non-fatal — we just skip this tick.
    pub(super) fn handle_traffic_sample(&mut self, result: Result<InterfaceBytes>) {
        // Reschedule unconditionally so a transient error doesn't stall the
        // sampler permanently.
        self.next_traffic_sample = Some(Instant::now() + SAMPLE_INTERVAL);

        let Some(session) = self.session.as_mut() else {
            return;
        };
        let Ok(bytes) = result else { return };
        session
            .traffic
            .record_sample(bytes.ibytes, bytes.obytes, Instant::now());
    }

    // ===== Small shared helpers =====

    /// Three startup branches all log the same "DHCP isn't running, you'll
    /// need to configure your router by hand" hint. Pulled out so they
    /// stay in lockstep.
    fn log_manual_router_config(&mut self) {
        let dns = self
            .session
            .as_ref()
            .map(|s| s.lan_ip.to_string())
            .unwrap_or_else(|| "this Mac".into());
        self.log_info(format!(
            "Configure router manually — gateway + DNS {dns} (port 53 is redirected anyway)"
        ));
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
