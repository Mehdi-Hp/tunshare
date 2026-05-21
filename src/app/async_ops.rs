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
    detect_lan_interfaces, detect_vpn_interfaces, discover_vpn_dns, dns::get_default_dns,
    DhcpServer, Firewall, InterfaceInfo, IpForwarding, NatPmpServer,
};

use super::App;

// ===== Constants =====

/// Per-operation timeouts. Tuned to "long enough that a healthy machine
/// always wins, short enough that a hung syscall doesn't strand the UI."
pub(super) const TIMEOUT_INTERFACES: Duration = Duration::from_secs(10);
pub(super) const TIMEOUT_DNS: Duration = Duration::from_secs(5);
pub(super) const TIMEOUT_START_SHARING: Duration = Duration::from_secs(10);
pub(super) const TIMEOUT_START_DHCP: Duration = Duration::from_secs(5);
pub(super) const TIMEOUT_START_NATPMP: Duration = Duration::from_secs(5);
pub(super) const TIMEOUT_STOP_SHARING: Duration = Duration::from_secs(10);
pub(super) const TIMEOUT_DEBUG_INFO: Duration = Duration::from_secs(5);
pub(super) const TIMEOUT_HEALTH_CHECK: Duration = Duration::from_secs(3);

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
        result: Result<()>,
        firewall: Firewall,
        ip_forwarding: IpForwarding,
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
    HealthCheck {
        status: HealthStatus,
    },
    DoctorFinished {
        results: Vec<CheckResult>,
    },
    DoctorAnchorFlushed {
        result: Result<()>,
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
        let mut session = crate::session::SharingSession::new(
            Firewall::new(),
            IpForwarding::new(),
            vpn_name.clone(),
            lan_name.clone(),
            lan_ip,
        );

        // Hand the firewall + IP forwarding managers to the spawn — they
        // come back via `AsyncOpResult::SharingStarted` even on cancellation
        // so the session can resume ownership and Drop cleans up properly.
        let (mut firewall, mut ip_forwarding) = session.take_managers();
        self.session = Some(session);

        let tx = self.op_tx.clone();
        tokio::spawn(async move {
            let result = timeout(TIMEOUT_START_SHARING, async {
                ip_forwarding.enable().await?;

                if let Err(e) = firewall.load_rules(&vpn_name, &lan_name).await {
                    let _ = ip_forwarding.restore().await;
                    return Err(e);
                }

                Ok(())
            })
            .await;

            let result = match result {
                Ok(inner) => inner,
                Err(_) => Err(TunshareError::FirewallError(
                    "starting sharing timed out".into(),
                )),
            };

            let _ = tx.send(AsyncOpResult::SharingStarted {
                result,
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
        let dns_servers = self.dns.effective();

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
        let vpn_name = session.vpn_name.clone();
        self.next_health_check = Some(Instant::now() + HEALTH_CHECK_INTERVAL);

        tokio::spawn(async move {
            let status = timeout(TIMEOUT_HEALTH_CHECK, health::check_health(&vpn_name))
                .await
                .unwrap_or(HealthStatus::Healthy); // Timeout = assume OK
            let _ = tx.send(AsyncOpResult::HealthCheck { status });
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
    }

    /// Kick off NAT-PMP startup if enabled. Returns true if a spawn was
    /// issued (caller should return early to let the result drive the next
    /// step), false if the caller should proceed to `finish_startup`.
    pub(super) fn maybe_start_natpmp(&mut self) -> bool {
        if self.natpmp_enabled {
            if let Some(session) = self.session.as_ref() {
                let vpn_name = session.vpn_name.clone();
                let lan_name = session.lan_name.clone();
                let lan_ip = session.lan_ip;
                self.start_natpmp_async(vpn_name, lan_name, lan_ip);
                return true;
            }
        }
        false
    }
}
