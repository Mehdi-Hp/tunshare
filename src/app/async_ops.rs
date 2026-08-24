//! Async operation plumbing: result/op-tag enums and every `tokio::spawn`
//! that pushes work onto a background task. These spawners are the only
//! place we hand state out to tokio tasks — result handling lives in
//! `super::result`.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use tokio::time::timeout;

use crate::doctor::{self, CheckResult};
use crate::error::{Result, TunshareError};
use crate::health::{self, HealthStatus};
use crate::system::{
    brew::find_brew, detect_lan_interfaces, detect_vpn_interfaces, detect_wan_uplink,
    discover_vpn_dns, dns::get_default_dns, load_list, read_interface_bytes, BypassConfig,
    DhcpServer, DnsServer, Firewall, InterfaceBytes, InterfaceInfo, IpForwarding, NatPmpServer,
    ResolverLists, WanDetect, WanUplink,
};

use super::App;

// ===== Constants =====

/// Per-operation timeouts. Tuned to "long enough that a healthy machine
/// always wins, short enough that a hung syscall doesn't strand the UI."
pub(super) const TIMEOUT_RELOAD_UPSTREAM: Duration = Duration::from_secs(10);
pub(super) const TIMEOUT_INTERFACES: Duration = Duration::from_secs(10);
pub(super) const TIMEOUT_DNS: Duration = Duration::from_secs(5);
pub(super) const TIMEOUT_START_SHARING: Duration = Duration::from_secs(15);
pub(super) const TIMEOUT_START_RESOLVER: Duration = Duration::from_secs(90);
pub(super) const TIMEOUT_LISTS: Duration = Duration::from_secs(90);
pub(super) const TIMEOUT_START_DHCP: Duration = Duration::from_secs(5);
pub(super) const TIMEOUT_START_NATPMP: Duration = Duration::from_secs(5);
pub(super) const TIMEOUT_STOP_SHARING: Duration = Duration::from_secs(10);
pub(super) const TIMEOUT_DEBUG_INFO: Duration = Duration::from_secs(5);
pub(super) const TIMEOUT_HEALTH_CHECK: Duration = Duration::from_secs(3);
pub(super) const TIMEOUT_TRAFFIC_SAMPLE: Duration = Duration::from_secs(2);

/// `brew install dnsmasq` can be slow: cold tap update, formula download,
/// dependency build. Generous ceiling — if we hit this, something's wrong.
pub(super) const TIMEOUT_INSTALL_DNSMASQ: Duration = Duration::from_secs(300);

/// Interval between periodic health checks while sharing is active.
pub(super) const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(10);

/// Faster recheck interval while the VPN is observed Down, so auto-stop
/// fires close to the configured timeout rather than rounded up to the
/// next 10-second tick.
pub(super) const HEALTH_RECHECK_DEGRADED: Duration = Duration::from_secs(3);

// ===== Types =====

/// Debug information about current system state.
#[derive(Debug, Clone, Default)]
pub struct DebugInfo {
    pub pf_rules: String,
    pub pf_states: String,
    pub pf_state_count: usize,
    pub pf_enabled: bool,
    pub ip_forwarding_modified: bool,
    pub ip_forwarding_enabled: bool,
    pub dhcp_running: bool,
    pub dhcp_range: Option<(String, String)>,
    pub natpmp_running: bool,
}

/// Result of an async operation. Each variant maps 1:1 with a spawner below.
pub enum AsyncOpResult {
    InterfacesDetected {
        vpn: Result<Vec<InterfaceInfo>>,
        lan: Result<Vec<InterfaceInfo>>,
    },
    DnsDiscovered {
        vpn_servers: Result<Vec<String>>,
        system_servers: Result<Vec<String>>,
    },
    SharingStarted {
        /// On success: the upstream we resolved (name + link MTU + effective
        /// clamp MTU) so the session can adopt it — the session is constructed
        /// with a placeholder (MTU=0) until this lands.
        result: Result<crate::session::ActiveUpstream>,
        wan: Option<WanDetect>,
        firewall: Firewall,
        ip_forwarding: IpForwarding,
    },
    ResolverStarted {
        result: Result<DnsServer>,
        block_count: usize,
        allow_count: usize,
        block_fetched: Option<std::time::SystemTime>,
        allow_fetched: Option<std::time::SystemTime>,
    },
    ListsRefreshed {
        block: crate::system::LoadedList,
        allow: crate::system::LoadedList,
        apply: bool,
    },
    FirewallReloaded {
        result: Result<()>,
        firewall: Firewall,
        allowlist_on: bool,
    },
    WanDetected {
        result: Result<WanDetect>,
    },
    DhcpStarted {
        result: Result<()>,
    },
    NatPmpStarted {
        result: Result<()>,
        server: Option<NatPmpServer>,
    },
    SharingStopped {
        result: Result<()>,
        firewall: Firewall,
        ip_forwarding: IpForwarding,
    },
    DebugInfoFetched {
        info: Result<DebugInfo>,
    },
    /// Rule reload after a VPN swap (default route moved to a new utun).
    /// On success: the new upstream (name + freshly-read MTU) so the
    /// session can adopt it. Firewall comes back so Drop cleans up.
    /// `natpmp_server` is the replacement handle if NAT-PMP was active
    /// before the reload (caller had stopped the old one).
    UpstreamReloaded {
        result: Result<crate::session::ActiveUpstream>,
        firewall: Firewall,
        natpmp_server: Option<NatPmpServer>,
    },
    HealthCheck {
        status: HealthStatus,
        /// Iface name on the current IPv4 default route, if any. Used by
        /// the result handler to detect VPN swaps (utunN → utunM) and
        /// dispatch `reload_upstream_async`. `None` when there's no
        /// default route or `route(8)` failed; both are treated as
        /// "don't reload" — the existing VPN-down path takes over.
        default_iface: Option<String>,
    },
    /// Periodic byte-counter sample for the VPN interface. `Err` is treated
    /// as a transient blip — we just skip the sample.
    TrafficSample {
        result: Result<InterfaceBytes>,
    },
    DoctorFinished {
        results: Vec<CheckResult>,
    },
    DoctorAnchorFlushed {
        result: Result<()>,
    },
    /// `brew install dnsmasq` finished. On failure, `stderr_tail` holds the
    /// last few lines of stderr for logging — full output would flood the
    /// log panel.
    DnsmasqInstalled {
        result: Result<()>,
        stderr_tail: String,
    },
}

/// Pending async operation (for UI display + stale-result guard).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingOp {
    DetectingInterfaces,
    DiscoveringDns,
    StartingSharing,
    StartingDhcp,
    StartingNatPmp,
    StoppingSharing,
    FetchingDebugInfo,
    RunningDoctor,
    FlushingStaleAnchor,
    InstallingDnsmasq,
    ReloadingUpstream,
    StartingResolver,
    RefreshingLists,
    ReloadingFirewall,
    DetectingWan,
}

impl PendingOp {
    pub fn display(&self) -> &'static str {
        match self {
            PendingOp::DetectingInterfaces => "Detecting interfaces...",
            PendingOp::DiscoveringDns => "Discovering DNS...",
            PendingOp::StartingSharing => "Starting VPN sharing...",
            PendingOp::StartingDhcp => "Starting DHCP server...",
            PendingOp::StartingNatPmp => "Starting NAT-PMP server...",
            PendingOp::StoppingSharing => "Stopping VPN sharing...",
            PendingOp::FetchingDebugInfo => "Fetching debug info...",
            PendingOp::RunningDoctor => "Running diagnostic checks...",
            PendingOp::FlushingStaleAnchor => "Flushing stale pf anchor...",
            PendingOp::InstallingDnsmasq => "Installing dnsmasq via Homebrew...",
            PendingOp::ReloadingUpstream => "Reloading rules for new VPN interface...",
            PendingOp::StartingResolver => "Starting DNS resolver...",
            PendingOp::RefreshingLists => "Refreshing domain filters...",
            PendingOp::ReloadingFirewall => "Reloading firewall rules...",
            PendingOp::DetectingWan => "Looking for a WAN uplink...",
        }
    }
}

/// Build a `CommandFailed` error tagged "operation timed out" — used by
/// every spawner to convert a `tokio::time::timeout` Elapsed into the
/// canonical error type.
fn timeout_err(command: &str) -> TunshareError {
    TunshareError::CommandFailed {
        command: command.into(),
        message: "operation timed out".into(),
    }
}

// ===== Spawners =====

impl App {
    /// Detect VPN + LAN interfaces. Bail if another op is already in flight.
    pub(super) fn refresh_interfaces_async(&mut self) {
        if self.pending_op.is_some() {
            return;
        }

        self.log_info("Detecting network interfaces...");
        self.set_pending_op(PendingOp::DetectingInterfaces);

        let tx = self.op_tx.clone();
        tokio::spawn(async move {
            let result = timeout(TIMEOUT_INTERFACES, async {
                let vpn = detect_vpn_interfaces().await;
                let lan = detect_lan_interfaces().await;
                (vpn, lan)
            })
            .await;

            let (vpn, lan) = match result {
                Ok(pair) => pair,
                Err(_) => (
                    Err(timeout_err("detect_interfaces")),
                    Err(timeout_err("detect_interfaces")),
                ),
            };
            let _ = tx.send(AsyncOpResult::InterfacesDetected { vpn, lan });
        });
    }

    /// Discover both VPN-specific and system-default DNS servers.
    pub(super) fn discover_dns_async(&mut self, vpn_name: String) {
        if self.pending_op.is_some() {
            return;
        }

        self.log_info(format!("Discovering DNS for {}...", vpn_name));
        self.set_pending_op(PendingOp::DiscoveringDns);

        let tx = self.op_tx.clone();
        tokio::spawn(async move {
            let result = timeout(TIMEOUT_DNS, async {
                tokio::join!(discover_vpn_dns(&vpn_name), get_default_dns())
            })
            .await;

            let (vpn_servers, system_servers) = match result {
                Ok(pair) => pair,
                Err(_) => (
                    Err(timeout_err("discover_dns")),
                    Err(timeout_err("discover_dns")),
                ),
            };
            let _ = tx.send(AsyncOpResult::DnsDiscovered {
                vpn_servers,
                system_servers,
            });
        });
    }

    /// Enable IP forwarding and load pf rules. On rule-load failure, restore
    /// IP forwarding before returning — keeps system state consistent even
    /// when sharing fails halfway through bringup.
    pub(super) fn start_sharing_async(
        &mut self,
        vpn_name: String,
        lan_name: String,
        lan_ip: Option<Ipv4Addr>,
    ) {
        if self.pending_op.is_some() {
            return;
        }

        self.log_info(format!(
            "Starting VPN sharing: {} -> {}",
            vpn_name, lan_name
        ));
        self.set_pending_op(PendingOp::StartingSharing);

        let lan_ip = lan_ip.unwrap_or(Ipv4Addr::UNSPECIFIED);
        // Placeholder upstream — the spawn resolves the real values via
        // `ActiveUpstream::detect` and emits them on `SharingStarted` so the
        // session's upstream gets filled in once rules are loaded. Until then
        // nothing reads its MTU fields (the spawn computes its own).
        let mut session = crate::session::SharingSession::new(
            Firewall::new(),
            IpForwarding::new(),
            crate::session::ActiveUpstream {
                name: vpn_name.clone(),
                link_mtu: 0,
                effective_mtu: 0,
            },
            lan_name.clone(),
            lan_ip,
        );

        // Hand the firewall + IP forwarding managers to the spawn — they
        // come back via `AsyncOpResult::SharingStarted` even on cancellation
        // so the session can resume ownership and Drop cleans up properly.
        let (mut firewall, mut ip_forwarding) = session.take_managers();
        self.session = Some(session);

        let mtu_policy = self.mtu.active;
        let allowlist_on = self.lists.allow.enabled;
        let tx = self.op_tx.clone();
        tokio::spawn(async move {
            let result =
                timeout(TIMEOUT_START_SHARING, async {
                    ip_forwarding.enable().await?;

                    let wan = if allowlist_on {
                        match detect_wan_uplink(&lan_name, std::slice::from_ref(&vpn_name)).await {
                            Ok(detect) => {
                                if detect.uplink.is_none() {
                                    let _ = ip_forwarding.restore().await;
                                    return Err(TunshareError::FirewallError(format!(
                                        "WAN bypass is on but no WAN uplink was found ({})",
                                        detect.miss_message()
                                    )));
                                }
                                Some(detect)
                            }
                            Err(error) => {
                                let _ = ip_forwarding.restore().await;
                                return Err(error);
                            }
                        }
                    } else {
                        None
                    };

                    // Resolve the upstream first (link MTU + the effective clamp
                    // MTU, which under `Auto` runs the path-MTU probe) so the pf
                    // scrub `max-mss` reflects the real path, not the tunnel's
                    // inflated interface MTU.
                    let upstream =
                        match crate::session::ActiveUpstream::detect(vpn_name.clone(), mtu_policy)
                            .await
                        {
                            Ok(u) => u,
                            Err(e) => {
                                let _ = ip_forwarding.restore().await;
                                return Err(e);
                            }
                        };

                    let bypass =
                        wan.as_ref()
                            .and_then(|detect| detect.uplink.as_ref())
                            .map(|uplink| BypassConfig {
                                wan_if: uplink.iface.clone(),
                                wan_gw: uplink.gateway,
                            });
                    if let Err(e) = firewall
                        .load_rules(
                            &upstream.name,
                            &lan_name,
                            lan_ip,
                            upstream.mss_v4(),
                            bypass.as_ref(),
                        )
                        .await
                    {
                        let _ = ip_forwarding.restore().await;
                        return Err(e);
                    }

                    Ok((upstream, wan))
                })
                .await;

            let (result, wan) = match result {
                Ok(Ok((upstream, wan))) => (Ok(upstream), wan),
                Ok(Err(error)) => (Err(error), None),
                Err(_) => (
                    Err(TunshareError::FirewallError(
                        "starting sharing timed out".into(),
                    )),
                    None,
                ),
            };

            let _ = tx.send(AsyncOpResult::SharingStarted {
                result,
                wan,
                firewall,
                ip_forwarding,
            });
        });
    }

    /// Start the dnsmasq-backed DHCP server.
    pub(super) fn start_dhcp_async(&mut self, lan_name: String, lan_ip: Ipv4Addr) {
        self.log_info("Starting DHCP server...");
        self.set_pending_op(PendingOp::StartingDhcp);

        if let Some(ref mut session) = self.session {
            session.dhcp_range = Some(DhcpServer::calculate_dhcp_range(lan_ip));
        }

        let tx = self.op_tx.clone();
        let dns_servers = vec![lan_ip.to_string()];

        tokio::spawn(async move {
            let result = timeout(TIMEOUT_START_DHCP, async {
                let mut dhcp = DhcpServer::new(&lan_name, lan_ip, dns_servers);
                dhcp.start().await
            })
            .await;

            let result = match result {
                Ok(inner) => inner,
                Err(_) => Err(timeout_err("start_dhcp")),
            };

            let _ = tx.send(AsyncOpResult::DhcpStarted { result });
        });
    }

    /// Start the embedded NAT-PMP server.
    pub(super) fn start_natpmp_async(
        &mut self,
        vpn_name: String,
        lan_name: String,
        lan_ip: Ipv4Addr,
    ) {
        self.log_info("Starting NAT-PMP server...");
        self.set_pending_op(PendingOp::StartingNatPmp);

        let tx = self.op_tx.clone();
        tokio::spawn(async move {
            let lan_network = NatPmpServer::network_from_ip(lan_ip);
            let server = NatPmpServer::new(&vpn_name, &lan_name, &lan_network);

            let result = timeout(TIMEOUT_START_NATPMP, server.start()).await;
            let (result, server) = match result {
                Ok(inner) => {
                    let server = if inner.is_ok() { Some(server) } else { None };
                    (inner, server)
                }
                Err(_) => (Err(timeout_err("start_natpmp")), None),
            };

            let _ = tx.send(AsyncOpResult::NatPmpStarted { result, server });
        });
    }

    /// Tear down sharing: NAT-PMP, DHCP, pf rules, IP forwarding — in that
    /// order. Aggregates per-step errors into one message.
    pub(super) fn stop_sharing_async(&mut self) {
        if self.pending_op.is_some() {
            return;
        }

        if self.session.is_none() {
            self.log_warning("VPN sharing is not active");
            self.state = super::AppState::Menu;
            return;
        }

        self.log_info("Stopping VPN sharing...");
        self.set_pending_op(PendingOp::StoppingSharing);

        let session = self
            .session
            .as_mut()
            .expect("session presence checked above");
        let dhcp_active = session.dhcp_active;
        let natpmp_active = session.natpmp_active;

        // Signal NAT-PMP server to shut down before spawning the cleanup task.
        session.shutdown_natpmp();
        session.shutdown_dns();

        let (mut firewall, mut ip_forwarding) = session.take_managers();
        let tx = self.op_tx.clone();

        tokio::spawn(async move {
            let result = timeout(TIMEOUT_STOP_SHARING, async {
                let mut errors = Vec::new();

                if natpmp_active {
                    if let Err(e) = NatPmpServer::stop().await {
                        errors.push(format!("NAT-PMP cleanup: {}", e));
                    }
                }

                if dhcp_active {
                    if let Err(e) = DhcpServer::stop().await {
                        errors.push(format!("DHCP cleanup: {}", e));
                    }
                }

                if let Err(e) = firewall.cleanup().await {
                    errors.push(format!("Firewall cleanup: {}", e));
                }

                if let Err(e) = ip_forwarding.restore().await {
                    errors.push(format!("IP forwarding: {}", e));
                }

                if errors.is_empty() {
                    Ok(())
                } else {
                    Err(TunshareError::FirewallError(errors.join("; ")))
                }
            })
            .await;

            let result = match result {
                Ok(inner) => inner,
                Err(_) => Err(TunshareError::FirewallError(
                    "stopping sharing timed out".into(),
                )),
            };

            let _ = tx.send(AsyncOpResult::SharingStopped {
                result,
                firewall,
                ip_forwarding,
            });
        });
    }

    /// Snapshot pf + IP-forwarding + session sub-server state for the debug pane.
    pub(super) fn fetch_debug_info_async(&mut self) {
        if self.pending_op.is_some() {
            return;
        }

        self.set_pending_op(PendingOp::FetchingDebugInfo);

        let tx = self.op_tx.clone();
        let ip_forwarding_modified = self
            .session
            .as_ref()
            .is_some_and(|s| s.ip_forwarding_is_modified());
        let dhcp_running = self.dhcp_active();
        let dhcp_range = self.dhcp_range().cloned();
        let natpmp_running = self.natpmp_active();

        tokio::spawn(async move {
            let info = timeout(TIMEOUT_DEBUG_INFO, async {
                let ip_fwd = IpForwarding::new();
                let (pf_rules, pf_states, pf_enabled, ip_fwd_state) = tokio::join!(
                    Firewall::get_current_rules(),
                    Firewall::get_current_states(),
                    Firewall::is_enabled(),
                    ip_fwd.get_state()
                );

                let pf_rules = pf_rules.unwrap_or_else(|e| format!("Error: {}", e));
                let pf_states = pf_states.unwrap_or_else(|e| format!("Error: {}", e));
                let pf_state_count = pf_states.lines().count().saturating_sub(1);
                let pf_enabled = pf_enabled.unwrap_or(false);
                let ip_forwarding_enabled = ip_fwd_state.unwrap_or(false);

                Ok(DebugInfo {
                    pf_rules,
                    pf_states,
                    pf_state_count,
                    pf_enabled,
                    ip_forwarding_modified,
                    ip_forwarding_enabled,
                    dhcp_running,
                    dhcp_range,
                    natpmp_running,
                })
            })
            .await;

            let info = match info {
                Ok(inner) => inner,
                Err(_) => Err(timeout_err("fetch_debug_info")),
            };

            let _ = tx.send(AsyncOpResult::DebugInfoFetched { info });
        });
    }

    /// Spawn a single health probe. Timer is bumped before the spawn so a
    /// hung probe can't stack with the next tick.
    pub(super) fn spawn_health_check(&mut self) {
        let Some(session) = self.session.as_ref() else {
            return;
        };

        let tx = self.op_tx.clone();
        let vpn_name = session.upstream.name.clone();
        self.next_health_check = Some(Instant::now() + HEALTH_CHECK_INTERVAL);

        tokio::spawn(async move {
            let probe = timeout(TIMEOUT_HEALTH_CHECK, async {
                let (status, default_iface) = tokio::join!(
                    health::check_health(&vpn_name),
                    crate::system::default_route_interface(),
                );
                (status, default_iface.ok().flatten())
            })
            .await;
            let (status, default_iface) = probe.unwrap_or((HealthStatus::Healthy, None)); // Timeout = assume OK
            let _ = tx.send(AsyncOpResult::HealthCheck {
                status,
                default_iface,
            });
        });
    }

    /// React to a default-route change: rebuild pf rules + LAN MTU
    /// against the new upstream utun, atomically replacing the old set.
    /// NAT-PMP (if active) is torn down here and restarted with the new
    /// external iface so port mappings advertise the right external IP.
    ///
    /// Bails early if anything else is in flight — the next health probe
    /// will see the new iface again and re-dispatch.
    pub(super) fn reload_upstream_async(&mut self, new_name: String) {
        if self.pending_op.is_some() || self.session.is_none() {
            return;
        }
        self.set_pending_op(PendingOp::ReloadingUpstream);

        let mtu_policy = self.mtu.active;
        // Re-fire DNS discovery for visibility (debug panel). Doesn't
        // touch `pending_op` — fire-and-forget so the reload owns the op.
        self.discover_dns_async_fire_and_forget(new_name.clone());

        // Borrow session mutably to grab the firewall + snapshot fields.
        let session = self.session.as_mut().expect("checked above");
        let (mut firewall, ip_forwarding) = session.take_managers();
        // Hand IP forwarding straight back — the swap doesn't touch it.
        // The firewall stays out for the duration of the reload spawn.
        session.restore_managers(Firewall::default(), ip_forwarding);
        let lan_name = session.lan_name.clone();
        let lan_ip = session.lan_ip;
        let session_wan = session.wan.clone();
        let natpmp_was_active = session.natpmp_active;
        if natpmp_was_active {
            // Stop the old server now so the spawn can spin up a fresh
            // one bound to the new ext iface.
            session.shutdown_natpmp();
        }

        let tx = self.op_tx.clone();
        tokio::spawn(async move {
            let outcome = timeout(TIMEOUT_RELOAD_UPSTREAM, async {
                // Re-resolve against the new tunnel — a different provider /
                // protocol means a different path MTU, so the probe re-runs
                // and the clamp tracks the swap.
                let upstream = crate::session::ActiveUpstream::detect(new_name, mtu_policy).await?;
                let bypass = session_wan.as_ref().map(|w| BypassConfig {
                    wan_if: w.iface.clone(),
                    wan_gw: w.gateway,
                });
                firewall
                    .load_rules(
                        &upstream.name,
                        &lan_name,
                        lan_ip,
                        upstream.mss_v4(),
                        bypass.as_ref(),
                    )
                    .await?;
                Ok::<_, TunshareError>(upstream)
            })
            .await;

            let (result, new_upstream_name) = match outcome {
                Ok(Ok(u)) => {
                    let n = u.name.clone();
                    (Ok(u), Some(n))
                }
                Ok(Err(e)) => (Err(e), None),
                Err(_) => (
                    Err(TunshareError::FirewallError(
                        "upstream reload timed out".into(),
                    )),
                    None,
                ),
            };

            // Restart NAT-PMP against the new upstream if it was active.
            // Failure here doesn't fail the reload — log and continue.
            let natpmp_server = if natpmp_was_active {
                if let Some(name) = new_upstream_name.as_deref() {
                    let lan_network = NatPmpServer::network_from_ip(lan_ip);
                    let server = NatPmpServer::new(name, &lan_name, &lan_network);
                    if server.start().await.is_ok() {
                        Some(server)
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            let _ = tx.send(AsyncOpResult::UpstreamReloaded {
                result,
                firewall,
                natpmp_server,
            });
        });
    }

    /// Fire-and-forget DNS discovery. Used by the upstream reactor — we
    /// want fresh `vpn_servers` for visibility but don't want to gate the
    /// reload on it (and don't want to touch `pending_op`, which is
    /// already held by the reload).
    fn discover_dns_async_fire_and_forget(&self, vpn_name: String) {
        let tx = self.op_tx.clone();
        tokio::spawn(async move {
            let result = timeout(TIMEOUT_DNS, async {
                tokio::join!(discover_vpn_dns(&vpn_name), get_default_dns())
            })
            .await;
            let (vpn_servers, system_servers) = match result {
                Ok(pair) => pair,
                Err(_) => return,
            };
            let _ = tx.send(AsyncOpResult::DnsDiscovered {
                vpn_servers,
                system_servers,
            });
        });
    }

    /// Spawn a single throughput sample for the VPN interface. Independent
    /// of `pending_op` since it runs throughout the session.
    pub(super) fn spawn_traffic_sample(&mut self) {
        let Some(session) = self.session.as_ref() else {
            return;
        };

        let tx = self.op_tx.clone();
        let vpn_name = session.upstream.name.clone();
        self.next_traffic_sample = Some(Instant::now() + super::traffic::SAMPLE_INTERVAL);

        tokio::spawn(async move {
            let result =
                match timeout(TIMEOUT_TRAFFIC_SAMPLE, read_interface_bytes(&vpn_name)).await {
                    Ok(inner) => inner,
                    Err(_) => Err(timeout_err("netstat traffic sample")),
                };
            let _ = tx.send(AsyncOpResult::TrafficSample { result });
        });
    }

    /// Run the doctor checks. Empty results table shows a spinner until the
    /// task completes.
    pub(super) fn run_doctor_async(&mut self) {
        if self.pending_op.is_some() {
            return;
        }
        self.set_pending_op(PendingOp::RunningDoctor);
        let tx = self.op_tx.clone();
        tokio::spawn(async move {
            let results = doctor::run_checks().await;
            let _ = tx.send(AsyncOpResult::DoctorFinished { results });
        });
    }

    /// Run `brew install dnsmasq`. Captures stdout/stderr; only the last
    /// few lines of stderr are surfaced (full brew output would flood the
    /// log panel). On success, `on_dnsmasq_installed` re-detects the
    /// binary and flips `dnsmasq_installed`.
    ///
    /// We're already running as root (the app requires sudo), but `brew`
    /// refuses to operate as root for safety. We drop privileges by
    /// shelling out via `sudo -u <SUDO_USER>` when `SUDO_USER` is set —
    /// which it always is when launched via `sudo tunshare`.
    pub(super) fn install_dnsmasq_async(&mut self) {
        if self.pending_op.is_some() {
            return;
        }

        let Some(brew_path) = find_brew() else {
            self.log_error("Homebrew not found — cannot install dnsmasq");
            return;
        };

        self.log_info("Installing dnsmasq via Homebrew (this may take a minute)...");
        self.set_pending_op(PendingOp::InstallingDnsmasq);

        let sudo_user = std::env::var("SUDO_USER").ok();
        let tx = self.op_tx.clone();

        tokio::spawn(async move {
            let mut cmd = if let Some(ref user) = sudo_user {
                let mut c = tokio::process::Command::new("sudo");
                c.args(["-u", user, &brew_path, "install", "dnsmasq"]);
                c
            } else {
                // No SUDO_USER — best-effort, brew will likely refuse.
                let mut c = tokio::process::Command::new(&brew_path);
                c.args(["install", "dnsmasq"]);
                c
            };

            let output = timeout(TIMEOUT_INSTALL_DNSMASQ, cmd.output()).await;

            let (result, stderr_tail) = match output {
                Ok(Ok(out)) if out.status.success() => (Ok(()), String::new()),
                Ok(Ok(out)) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    let tail: String = stderr
                        .lines()
                        .rev()
                        .take(5)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .collect::<Vec<_>>()
                        .join("\n");
                    (
                        Err(TunshareError::CommandFailed {
                            command: "brew install dnsmasq".into(),
                            message: format!("exit status {}", out.status),
                        }),
                        tail,
                    )
                }
                Ok(Err(e)) => (
                    Err(TunshareError::CommandFailed {
                        command: "brew install dnsmasq".into(),
                        message: e.to_string(),
                    }),
                    String::new(),
                ),
                Err(_) => (Err(timeout_err("brew install dnsmasq")), String::new()),
            };

            let _ = tx.send(AsyncOpResult::DnsmasqInstalled {
                result,
                stderr_tail,
            });
        });
    }

    /// Flush the stale pf anchor; result triggers a fresh doctor run.
    pub(super) fn flush_stale_anchor_async(&mut self) {
        if self.pending_op.is_some() {
            return;
        }
        self.set_pending_op(PendingOp::FlushingStaleAnchor);
        let tx = self.op_tx.clone();
        tokio::spawn(async move {
            let result = doctor::flush_stale_anchor().await;
            let _ = tx.send(AsyncOpResult::DoctorAnchorFlushed { result });
        });
    }

    // ===== Startup orchestration =====

    /// Clear pending startup state and transition to Active. Called once
    /// the final startup-chain step (sharing → DHCP → NAT-PMP) completes.
    pub(super) fn finish_startup(&mut self) {
        self.clear_pending_op();
        self.state = super::AppState::Active;
        self.next_health_check = Some(Instant::now() + HEALTH_CHECK_INTERVAL);
        // Take the first traffic sample right away so the sparkline starts
        // populating instead of staying blank for the first second.
        self.next_traffic_sample = Some(Instant::now());
    }

    /// Kick off NAT-PMP startup if enabled. Returns true if a spawn was
    /// issued (caller should return early to let the result drive the next
    /// step), false if the caller should proceed to `finish_startup`.
    pub(super) fn maybe_start_resolver(&mut self) -> bool {
        let Some(session) = self.session.as_ref() else {
            return false;
        };
        let lan_ip = session.lan_ip;
        let wan = session.wan.clone();
        let vpn_dns = self.dns.effective();
        let wan_dns = if self.dns.system_servers.is_empty() {
            vec!["1.1.1.1".to_string()]
        } else {
            self.dns.system_servers.clone()
        };
        let block_setting = self.lists.block.clone();
        let allow_setting = self.lists.allow.clone();
        self.set_pending_op(PendingOp::StartingResolver);
        self.log_info("Starting LAN DNS resolver...");
        let tx = self.op_tx.clone();
        tokio::spawn(async move {
            let result = timeout(TIMEOUT_START_RESOLVER, async {
                let (block, allow) = tokio::join!(
                    load_list(&block_setting, false),
                    load_list(&allow_setting, false),
                );
                let lists = ResolverLists {
                    block: if block_setting.enabled {
                        block.set.clone()
                    } else {
                        Default::default()
                    },
                    allow: if allow_setting.enabled {
                        allow.set.clone()
                    } else {
                        Default::default()
                    },
                    block_enabled: block_setting.enabled,
                    allow_enabled: allow_setting.enabled,
                };
                let server =
                    DnsServer::start(lan_ip, vpn_dns, wan_dns, wan.as_ref(), lists).await?;
                Ok((server, block, allow))
            })
            .await;
            match result {
                Ok(Ok((server, block, allow))) => {
                    let _ = tx.send(AsyncOpResult::ResolverStarted {
                        result: Ok(server),
                        block_count: block.set.len(),
                        allow_count: allow.set.len(),
                        block_fetched: block.last_fetch,
                        allow_fetched: allow.last_fetch,
                    });
                }
                Ok(Err(error)) => {
                    let _ = tx.send(AsyncOpResult::ResolverStarted {
                        result: Err(error),
                        block_count: 0,
                        allow_count: 0,
                        block_fetched: None,
                        allow_fetched: None,
                    });
                }
                Err(_) => {
                    let _ = tx.send(AsyncOpResult::ResolverStarted {
                        result: Err(timeout_err("start_resolver")),
                        block_count: 0,
                        allow_count: 0,
                        block_fetched: None,
                        allow_fetched: None,
                    });
                }
            }
        });
        true
    }

    pub(super) fn refresh_lists_async(&mut self, apply: bool) {
        if self.pending_op.is_some() {
            return;
        }
        self.set_pending_op(PendingOp::RefreshingLists);
        self.log_info("Refreshing domain filters...");
        let block_setting = self.lists.block.clone();
        let allow_setting = self.lists.allow.clone();
        let tx = self.op_tx.clone();
        tokio::spawn(async move {
            let result = timeout(TIMEOUT_LISTS, async {
                tokio::join!(
                    load_list(&block_setting, true),
                    load_list(&allow_setting, true),
                )
            })
            .await;
            let (block, allow) = result.unwrap_or_default();
            let _ = tx.send(AsyncOpResult::ListsRefreshed {
                block,
                allow,
                apply,
            });
        });
    }

    pub(super) fn detect_wan_async(&mut self, share_iface: String, exclude: Vec<String>) {
        if self.pending_op.is_some() {
            return;
        }
        self.set_pending_op(PendingOp::DetectingWan);
        self.log_info("Looking for a WAN uplink...");
        let tx = self.op_tx.clone();
        tokio::spawn(async move {
            let result = timeout(
                TIMEOUT_INTERFACES,
                detect_wan_uplink(&share_iface, &exclude),
            )
            .await;
            let result = match result {
                Ok(inner) => inner,
                Err(_) => Err(timeout_err("detect_wan")),
            };
            let _ = tx.send(AsyncOpResult::WanDetected { result });
        });
    }

    pub(super) fn reload_firewall_for_bypass_async(&mut self, wan: WanUplink) {
        let bypass = Some(BypassConfig {
            wan_if: wan.iface.clone(),
            wan_gw: wan.gateway,
        });
        self.reload_firewall_async(bypass, true);
    }

    pub(super) fn reload_firewall_without_bypass_async(&mut self) {
        self.reload_firewall_async(None, false);
    }

    fn reload_firewall_async(&mut self, bypass: Option<BypassConfig>, allowlist_on: bool) {
        if self.pending_op.is_some() || self.session.is_none() {
            return;
        }
        self.set_pending_op(PendingOp::ReloadingFirewall);
        let session = self.session.as_mut().expect("checked above");
        let (mut firewall, ip_forwarding) = session.take_managers();
        session.restore_managers(Firewall::default(), ip_forwarding);
        let vpn_name = session.upstream.name.clone();
        let lan_name = session.lan_name.clone();
        let lan_ip = session.lan_ip;
        let mss = session.upstream.mss_v4();
        let tx = self.op_tx.clone();
        tokio::spawn(async move {
            let result = timeout(TIMEOUT_RELOAD_UPSTREAM, async {
                firewall
                    .load_rules(&vpn_name, &lan_name, lan_ip, mss, bypass.as_ref())
                    .await
            })
            .await;
            let result = match result {
                Ok(inner) => inner,
                Err(_) => Err(timeout_err("reload_firewall")),
            };
            if !allowlist_on {
                Firewall::table_flush();
            }
            let _ = tx.send(AsyncOpResult::FirewallReloaded {
                result,
                firewall,
                allowlist_on,
            });
        });
    }

    /// Kick off NAT-PMP startup if enabled. Returns true if a spawn was
    /// issued (caller should return early to let the result drive the next
    /// step), false if the caller should proceed to `finish_startup`.
    pub(super) fn maybe_start_natpmp(&mut self) -> bool {
        if self.natpmp_enabled {
            if let Some(session) = self.session.as_ref() {
                let vpn_name = session.upstream.name.clone();
                let lan_name = session.lan_name.clone();
                let lan_ip = session.lan_ip;
                self.start_natpmp_async(vpn_name, lan_name, lan_ip);
                return true;
            }
        }
        false
    }
}
