//! Application state and message handling (Elm architecture) with async support.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use crate::error::Result;
use crate::session::SharingSession;
use crate::system::{
    detect_lan_interfaces, detect_vpn_interfaces, discover_vpn_dns, dns::get_default_dns,
    DhcpServer, Firewall, InterfaceInfo, IpForwarding, NatPmpServer,
};
use crate::ui::status::LogEntryLevel;
use tokio::sync::mpsc;

/// Maximum number of log entries kept in memory.
const MAX_LOG_ENTRIES: usize = 500;

/// Timeout durations for async operations.
const TIMEOUT_INTERFACES: Duration = Duration::from_secs(10);
const TIMEOUT_DNS: Duration = Duration::from_secs(5);
const TIMEOUT_START_SHARING: Duration = Duration::from_secs(10);
const TIMEOUT_START_DHCP: Duration = Duration::from_secs(5);
const TIMEOUT_START_NATPMP: Duration = Duration::from_secs(5);
const TIMEOUT_STOP_SHARING: Duration = Duration::from_secs(10);
const TIMEOUT_DEBUG_INFO: Duration = Duration::from_secs(5);

/// Debug information about current system state.
#[derive(Debug, Clone, Default)]
pub struct DebugInfo {
    /// Current pf rules.
    pub pf_rules: String,
    /// Current pf states (count and sample).
    pub pf_states: String,
    /// Number of active pf states.
    pub pf_state_count: usize,
    /// Whether pf is enabled.
    pub pf_enabled: bool,
    /// Whether we've modified IP forwarding.
    pub ip_forwarding_modified: bool,
    /// Current IP forwarding state.
    pub ip_forwarding_enabled: bool,
    /// Whether DHCP server is running.
    pub dhcp_running: bool,
    /// DHCP range if enabled.
    pub dhcp_range: Option<(String, String)>,
    /// Whether NAT-PMP server is running.
    pub natpmp_running: bool,
}

/// Result of an async operation.
pub enum AsyncOpResult {
    /// Interface detection completed.
    InterfacesDetected {
        vpn: Result<Vec<InterfaceInfo>>,
        lan: Result<Vec<InterfaceInfo>>,
    },
    /// DNS discovery completed.
    DnsDiscovered {
        vpn_servers: Result<Vec<String>>,
        system_servers: Result<Vec<String>>,
    },
    /// VPN sharing started (firewall rules loaded).
    SharingStarted {
        result: Result<()>,
        firewall: Firewall,
        ip_forwarding: IpForwarding,
    },
    /// DHCP server started.
    DhcpStarted { result: Result<()> },
    /// NAT-PMP server started.
    NatPmpStarted {
        result: Result<()>,
        server: Option<NatPmpServer>,
    },
    /// VPN sharing stopped.
    SharingStopped {
        result: Result<()>,
        firewall: Firewall,
        ip_forwarding: IpForwarding,
    },
    /// Debug info fetched.
    DebugInfoFetched { info: Result<DebugInfo> },
}

/// Pending async operation type (for UI display).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingOp {
    /// Detecting network interfaces.
    DetectingInterfaces,
    /// Discovering DNS servers.
    DiscoveringDns,
    /// Starting VPN sharing.
    StartingSharing,
    /// Starting DHCP server.
    StartingDhcp,
    /// Starting NAT-PMP server.
    StartingNatPmp,
    /// Stopping VPN sharing.
    StoppingSharing,
    /// Fetching debug info.
    FetchingDebugInfo,
}

impl PendingOp {
    /// Get display text for the operation.
    pub fn display(&self) -> &'static str {
        match self {
            PendingOp::DetectingInterfaces => "Detecting interfaces...",
            PendingOp::DiscoveringDns => "Discovering DNS...",
            PendingOp::StartingSharing => "Starting VPN sharing...",
            PendingOp::StartingDhcp => "Starting DHCP server...",
            PendingOp::StartingNatPmp => "Starting NAT-PMP server...",
            PendingOp::StoppingSharing => "Stopping VPN sharing...",
            PendingOp::FetchingDebugInfo => "Fetching debug info...",
        }
    }
}

/// A DNS preset entry.
#[derive(Debug, Clone)]
pub struct DnsPreset {
    pub name: &'static str,
    pub ip: &'static str,
}

/// Well-known DNS presets.
pub const DNS_PRESETS: &[DnsPreset] = &[
    DnsPreset {
        name: "Cloudflare",
        ip: "1.1.1.1",
    },
    DnsPreset {
        name: "Google",
        ip: "8.8.8.8",
    },
    DnsPreset {
        name: "Quad9",
        ip: "9.9.9.9",
    },
    DnsPreset {
        name: "OpenDNS",
        ip: "208.67.222.222",
    },
];

/// DNS edit sub-mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsEditMode {
    /// Selecting from the preset list.
    SelectingPreset,
    /// Typing a custom IP.
    CustomInput,
}

/// DNS configuration and edit state.
pub struct DnsConfig {
    /// DNS servers discovered for the VPN.
    pub vpn_servers: Vec<String>,
    /// System default DNS servers.
    pub system_servers: Vec<String>,
    /// User-specified custom DNS server (overrides auto-detected).
    pub custom: Option<String>,
    /// Text input buffer for DNS editing.
    pub input_buffer: String,
    /// DNS edit sub-mode (preset list vs custom input).
    pub edit_mode: DnsEditMode,
    /// Selected index in the DNS preset list (0=Auto-detect, 1..N=presets, N+1=Custom...).
    pub preset_selected: usize,
}

impl DnsConfig {
    fn new() -> Self {
        Self {
            vpn_servers: Vec::new(),
            system_servers: Vec::new(),
            custom: None,
            input_buffer: String::new(),
            edit_mode: DnsEditMode::SelectingPreset,
            preset_selected: 0,
        }
    }

    /// Get the effective DNS servers (custom > vpn > system).
    pub fn effective(&self) -> Vec<String> {
        if let Some(ref dns) = self.custom {
            vec![dns.clone()]
        } else if !self.vpn_servers.is_empty() {
            self.vpn_servers.clone()
        } else {
            self.system_servers.clone()
        }
    }

    /// Get the source label for the current DNS.
    pub fn source(&self) -> &'static str {
        if self.custom.is_some() {
            "custom"
        } else if !self.vpn_servers.is_empty() {
            "vpn"
        } else if !self.system_servers.is_empty() {
            "system"
        } else {
            "none"
        }
    }
}

/// Application state.
pub struct App {
    /// Detected VPN interfaces.
    pub vpn_interfaces: Vec<InterfaceInfo>,
    /// Detected LAN interfaces.
    pub lan_interfaces: Vec<InterfaceInfo>,
    /// DNS configuration and edit state.
    pub dns: DnsConfig,
    /// Currently selected VPN interface index.
    pub selected_vpn: Option<usize>,
    /// Currently selected LAN interface index.
    pub selected_lan: Option<usize>,
    /// Active sharing session (None when not sharing).
    pub session: Option<SharingSession>,
    /// Log entries for display (bounded ring buffer).
    pub logs: VecDeque<LogEntry>,
    /// Current UI state.
    pub state: AppState,
    /// Selected menu item index.
    pub selected_menu_item: usize,
    /// Whether the app should quit.
    pub should_quit: bool,
    /// Channel sender for async operation results.
    op_tx: mpsc::UnboundedSender<AsyncOpResult>,
    /// Channel receiver for async operation results.
    op_rx: mpsc::UnboundedReceiver<AsyncOpResult>,
    /// Currently pending async operation.
    pub pending_op: Option<PendingOp>,
    /// When the current pending operation started (for elapsed time display).
    pub pending_op_started: Option<Instant>,
    /// Whether to show debug panel.
    pub show_debug: bool,
    /// Cached debug information.
    pub debug_info: Option<DebugInfo>,
    /// Whether the log panel is expanded.
    pub logs_expanded: bool,
    /// User preference: whether to start DHCP when sharing (default: true if dnsmasq installed).
    pub dhcp_enabled: bool,
    /// User preference: whether to start NAT-PMP when sharing (default: true).
    pub natpmp_enabled: bool,
    /// Cached: is dnsmasq installed on this system.
    pub dnsmasq_installed: bool,
}

/// Log entry for the status panel.
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: String,
    pub message: String,
    pub level: LogEntryLevel,
}

/// Current UI state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppState {
    /// Main menu.
    Menu,
    /// Selecting VPN interface.
    SelectingVpn,
    /// Selecting LAN interface.
    SelectingLan,
    /// Sharing is active, showing status.
    Active,
    /// Editing custom DNS server.
    EditingDns,
}

/// Menu items.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuItem {
    StartSharing,
    StopSharing,
    ToggleDhcp,
    ToggleNatPmp,
    SetDns,
    Quit,
}

impl App {
    /// Create a new application instance.
    pub fn new() -> Self {
        let (op_tx, op_rx) = mpsc::unbounded_channel();

        // Check for dnsmasq on startup
        let dnsmasq_available = DhcpServer::is_dnsmasq_installed();

        let mut app = Self {
            vpn_interfaces: Vec::new(),
            lan_interfaces: Vec::new(),
            dns: DnsConfig::new(),
            selected_vpn: None,
            selected_lan: None,
            session: None,
            logs: VecDeque::with_capacity(MAX_LOG_ENTRIES),
            state: AppState::Menu,
            selected_menu_item: 0,
            should_quit: false,
            op_tx,
            op_rx,
            pending_op: None,
            pending_op_started: None,
            show_debug: false,
            debug_info: None,
            logs_expanded: false,
            dhcp_enabled: dnsmasq_available,
            natpmp_enabled: true,
            dnsmasq_installed: dnsmasq_available,
        };

        app.log_info("Ready. Press Enter to start VPN sharing.");
        if !dnsmasq_available {
            app.log_warning("dnsmasq not found. Install with: brew install dnsmasq");
            app.log_info("DHCP will be disabled; router needs manual IP config.");
        }
        app
    }

    /// Whether VPN sharing is currently active.
    pub fn is_sharing(&self) -> bool {
        self.session.is_some()
    }

    /// Whether DHCP server is active (false if not sharing).
    pub fn dhcp_active(&self) -> bool {
        self.session.as_ref().is_some_and(|s| s.dhcp_active)
    }

    /// Whether NAT-PMP server is active (false if not sharing).
    pub fn natpmp_active(&self) -> bool {
        self.session.as_ref().is_some_and(|s| s.natpmp_active)
    }

    /// DHCP range (None if not sharing or DHCP inactive).
    pub fn dhcp_range(&self) -> Option<&(String, String)> {
        self.session.as_ref().and_then(|s| s.dhcp_range.as_ref())
    }

    /// Check if there's a pending operation (UI should show loading indicator).
    #[allow(dead_code)]
    pub fn is_loading(&self) -> bool {
        self.pending_op.is_some()
    }

    /// Set the pending operation and record its start time.
    fn set_pending_op(&mut self, op: PendingOp) {
        self.pending_op = Some(op);
        self.pending_op_started = Some(Instant::now());
    }

    /// Clear the pending operation and its start time.
    fn clear_pending_op(&mut self) {
        self.pending_op = None;
        self.pending_op_started = None;
    }

    /// Get elapsed time since the pending operation started.
    pub fn pending_elapsed(&self) -> Option<Duration> {
        self.pending_op_started.map(|start| start.elapsed())
    }

    /// Cancel the currently pending operation.
    /// The spawned tokio task will still run to completion, but its result
    /// will be detected as stale and discarded (except SharingStarted/SharingStopped
    /// which always restore firewall/ip_forwarding ownership).
    fn cancel_pending_op(&mut self) {
        if let Some(op) = self.pending_op {
            self.log_warning(format!("Cancelled: {}", op.display()));
            self.clear_pending_op();

            // Return to an appropriate state
            match op {
                PendingOp::DetectingInterfaces => {
                    self.state = AppState::Menu;
                }
                PendingOp::DiscoveringDns => {
                    self.state = AppState::SelectingVpn;
                }
                PendingOp::StartingSharing
                | PendingOp::StartingDhcp
                | PendingOp::StartingNatPmp => {
                    // If sharing was already marked active (e.g. DHCP/NAT-PMP phase), stay in Menu
                    self.state = AppState::Menu;
                }
                PendingOp::StoppingSharing => {
                    // Can't really undo a stop -- stay in current state, result will arrive
                    // and handle cleanup via the always-restore path for SharingStopped
                }
                PendingOp::FetchingDebugInfo => {
                    // Just dismiss, stay where we are
                }
            }
        }
    }

    /// Poll for async operation results. Call this from the main loop.
    pub fn poll_async_results(&mut self) {
        while let Ok(result) = self.op_rx.try_recv() {
            self.handle_async_result(result);
        }
    }

    /// Check whether the incoming result matches the currently pending operation.
    /// SharingStarted/SharingStopped always match because we must restore ownership
    /// of firewall/ip_forwarding regardless.
    fn result_matches_pending(&self, result: &AsyncOpResult) -> bool {
        match (result, self.pending_op) {
            // These carry firewall/ip_forwarding -- always accept
            (AsyncOpResult::SharingStarted { .. }, _) => true,
            (AsyncOpResult::SharingStopped { .. }, _) => true,
            // Normal matching
            (AsyncOpResult::InterfacesDetected { .. }, Some(PendingOp::DetectingInterfaces)) => {
                true
            }
            (AsyncOpResult::DnsDiscovered { .. }, Some(PendingOp::DiscoveringDns)) => true,
            (AsyncOpResult::DhcpStarted { .. }, Some(PendingOp::StartingDhcp)) => true,
            (AsyncOpResult::NatPmpStarted { .. }, Some(PendingOp::StartingNatPmp)) => true,
            (AsyncOpResult::DebugInfoFetched { .. }, Some(PendingOp::FetchingDebugInfo)) => true,
            _ => false,
        }
    }

    /// Handle a completed async operation.
    fn handle_async_result(&mut self, result: AsyncOpResult) {
        // Guard against stale results (user cancelled, or a different op is now pending).
        // SharingStarted/SharingStopped are exempt because we must always restore
        // firewall/ip_forwarding ownership to prevent Drop cleanup.
        if !self.result_matches_pending(&result) {
            // For SharingStarted/SharingStopped the match above returns true,
            // so we only reach here for truly stale lightweight results.
            self.log_info("Discarded stale async result");
            return;
        }

        match result {
            AsyncOpResult::InterfacesDetected { vpn, lan } => {
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

                // Continue to interface selection if we have interfaces
                if !self.vpn_interfaces.is_empty() && !self.lan_interfaces.is_empty() {
                    self.state = AppState::SelectingVpn;
                    self.selected_vpn = Some(0);
                    self.log_info("Select VPN interface to share from");
                } else if self.vpn_interfaces.is_empty() {
                    self.log_error("No VPN interfaces found. Connect to VPN first.");
                } else {
                    self.log_error("No LAN interfaces found.");
                }
            }
            AsyncOpResult::DnsDiscovered {
                vpn_servers,
                system_servers,
            } => {
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
                    Err(_) => {
                        self.dns.system_servers.clear();
                    }
                }

                // Continue to LAN selection
                self.state = AppState::SelectingLan;
                self.selected_lan = if self.lan_interfaces.is_empty() {
                    None
                } else {
                    Some(0)
                };
                self.log_info("Select LAN interface to share to");
            }
            AsyncOpResult::SharingStarted {
                result,
                firewall,
                ip_forwarding,
            } => {
                // ALWAYS restore managers to prevent Drop cleanup, even if cancelled
                if let Some(ref mut session) = self.session {
                    session.restore_managers(firewall, ip_forwarding);
                }

                // If the user cancelled, don't proceed with the startup flow
                if self.pending_op != Some(PendingOp::StartingSharing) {
                    self.log_info("Sharing result arrived after cancel (resources restored)");
                    return;
                }

                match result {
                    Ok(()) => {
                        let lan_ip_display = self
                            .session
                            .as_ref()
                            .map(|s| s.lan_ip.to_string())
                            .unwrap_or_else(|| "unknown".into());
                        self.log_success(format!(
                            "VPN sharing active! Gateway: {}",
                            lan_ip_display
                        ));

                        // Try to start DHCP server if enabled and dnsmasq is available
                        if self.dhcp_enabled && self.dnsmasq_installed {
                            if let Some(session) = self.session.as_ref() {
                                let lan_name = session.lan_name.clone();
                                let lan_ip = session.lan_ip;
                                self.start_dhcp_async(lan_name, lan_ip);
                                return;
                            }
                        } else if !self.dhcp_enabled {
                            self.log_info("DHCP disabled by user preference");
                            let eff = self.dns.effective();
                            if !eff.is_empty() {
                                self.log_info(format!(
                                    "Configure router manually - DNS: {}",
                                    eff.join(", ")
                                ));
                            }
                        } else {
                            self.log_info("DHCP disabled (dnsmasq not installed)");
                            let eff = self.dns.effective();
                            if !eff.is_empty() {
                                self.log_info(format!(
                                    "Configure router manually - DNS: {}",
                                    eff.join(", ")
                                ));
                            }
                        }

                        // No DHCP - try NAT-PMP or go directly to active state
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
            AsyncOpResult::DhcpStarted { result } => {
                match result {
                    Ok(()) => {
                        let log_msg = if let Some(ref mut session) = self.session {
                            session.dhcp_active = true;
                            match &session.dhcp_range {
                                Some((start, end)) => {
                                    format!("DHCP server active ({}-{})", start, end)
                                }
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
                        self.log_info("Router needs manual IP configuration");
                        let eff = self.dns.effective();
                        if !eff.is_empty() {
                            self.log_info(format!(
                                "Configure router manually - DNS: {}",
                                eff.join(", ")
                            ));
                        }
                    }
                }

                // Try to start NAT-PMP server if enabled
                if self.maybe_start_natpmp() {
                    return;
                }

                self.finish_startup();
            }
            AsyncOpResult::NatPmpStarted { result, server } => {
                match result {
                    Ok(()) => {
                        if let Some(ref mut session) = self.session {
                            session.natpmp_active = true;
                            session.set_natpmp_server(server);
                        }
                        self.log_success("NAT-PMP server active");
                    }
                    Err(e) => {
                        self.log_warning(format!("NAT-PMP server failed: {}", e));
                    }
                }

                self.finish_startup();
            }
            AsyncOpResult::SharingStopped {
                result,
                firewall,
                ip_forwarding,
            } => {
                // Restore managers before dropping session (prevents double cleanup)
                if let Some(ref mut session) = self.session {
                    session.restore_managers(firewall, ip_forwarding);
                }
                self.clear_pending_op();

                match result {
                    Ok(()) => {
                        self.log_success("VPN sharing stopped");
                    }
                    Err(e) => {
                        self.log_error(format!("Cleanup warning: {}", e));
                    }
                }

                // Drop session (its Drop is a no-op because async cleanup already ran)
                self.session = None;
                self.state = AppState::Menu;
                self.selected_menu_item = 0;
                self.show_debug = false;
                self.debug_info = None;
            }
            AsyncOpResult::DebugInfoFetched { info } => {
                self.clear_pending_op();

                match info {
                    Ok(debug_info) => {
                        self.debug_info = Some(debug_info);
                    }
                    Err(e) => {
                        self.log_warning(format!("Failed to fetch debug info: {}", e));
                        self.debug_info = None;
                    }
                }
            }
        }
    }

    /// Clear pending startup state and transition to Active.
    fn finish_startup(&mut self) {
        self.clear_pending_op();
        self.state = AppState::Active;
    }

    /// Try to start NAT-PMP if enabled.
    /// Returns `true` if NAT-PMP startup was launched (caller should return early).
    fn maybe_start_natpmp(&mut self) -> bool {
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

    /// Get the menu items based on current state.
    pub fn menu_items(&self) -> Vec<MenuItem> {
        if self.is_sharing() {
            vec![MenuItem::StopSharing, MenuItem::Quit]
        } else {
            vec![
                MenuItem::StartSharing,
                MenuItem::ToggleDhcp,
                MenuItem::ToggleNatPmp,
                MenuItem::SetDns,
                MenuItem::Quit,
            ]
        }
    }

    /// Refresh interface lists (async).
    fn refresh_interfaces_async(&mut self) {
        if self.pending_op.is_some() {
            return; // Already busy
        }

        self.log_info("Detecting network interfaces...");
        self.set_pending_op(PendingOp::DetectingInterfaces);

        let tx = self.op_tx.clone();
        tokio::spawn(async move {
            let result = tokio::time::timeout(TIMEOUT_INTERFACES, async {
                let vpn = detect_vpn_interfaces().await;
                let lan = detect_lan_interfaces().await;
                (vpn, lan)
            })
            .await;

            let (vpn, lan) = match result {
                Ok(pair) => pair,
                Err(_) => {
                    let err = || {
                        Err(crate::error::TunshareError::CommandFailed {
                            command: "detect_interfaces".into(),
                            message: "operation timed out".into(),
                        })
                    };
                    (err(), err())
                }
            };
            let _ = tx.send(AsyncOpResult::InterfacesDetected { vpn, lan });
        });
    }

    /// Discover DNS servers for VPN interface (async).
    fn discover_dns_async(&mut self, vpn_name: String) {
        if self.pending_op.is_some() {
            return; // Already busy
        }

        self.log_info(format!("Discovering DNS for {}...", vpn_name));
        self.set_pending_op(PendingOp::DiscoveringDns);

        let tx = self.op_tx.clone();
        tokio::spawn(async move {
            let result = tokio::time::timeout(TIMEOUT_DNS, async {
                tokio::join!(discover_vpn_dns(&vpn_name), get_default_dns())
            })
            .await;

            let (vpn_servers, system_servers) = match result {
                Ok(pair) => pair,
                Err(_) => {
                    let err = || {
                        Err(crate::error::TunshareError::CommandFailed {
                            command: "discover_dns".into(),
                            message: "operation timed out".into(),
                        })
                    };
                    (err(), err())
                }
            };
            let _ = tx.send(AsyncOpResult::DnsDiscovered {
                vpn_servers,
                system_servers,
            });
        });
    }

    /// Start VPN sharing (async).
    fn start_sharing_async(
        &mut self,
        vpn_name: String,
        lan_name: String,
        lan_ip: Option<Ipv4Addr>,
    ) {
        if self.pending_op.is_some() {
            return; // Already busy
        }

        self.log_info(format!(
            "Starting VPN sharing: {} -> {}",
            vpn_name, lan_name
        ));
        self.set_pending_op(PendingOp::StartingSharing);

        // Create session with fresh managers
        let lan_ip = lan_ip.unwrap_or(Ipv4Addr::UNSPECIFIED);
        let mut session = SharingSession::new(
            Firewall::new(),
            IpForwarding::new(),
            vpn_name.clone(),
            lan_name.clone(),
            lan_ip,
        );

        // Take managers out for async operation
        let (mut firewall, mut ip_forwarding) = session.take_managers();
        self.session = Some(session);

        let tx = self.op_tx.clone();

        tokio::spawn(async move {
            let result = tokio::time::timeout(TIMEOUT_START_SHARING, async {
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
                Err(_) => Err(crate::error::TunshareError::FirewallError(
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

    /// Start DHCP server (async).
    fn start_dhcp_async(&mut self, lan_name: String, lan_ip: Ipv4Addr) {
        self.log_info("Starting DHCP server...");
        self.set_pending_op(PendingOp::StartingDhcp);

        // Calculate and store the DHCP range on the session
        if let Some(ref mut session) = self.session {
            session.dhcp_range = Some(DhcpServer::calculate_dhcp_range(lan_ip));
        }

        let tx = self.op_tx.clone();
        let dns_servers = self.dns.effective();

        tokio::spawn(async move {
            let result = tokio::time::timeout(TIMEOUT_START_DHCP, async {
                let mut dhcp = DhcpServer::new(&lan_name, lan_ip, dns_servers);
                dhcp.start().await
            })
            .await;

            let result = match result {
                Ok(inner) => inner,
                Err(_) => Err(crate::error::TunshareError::CommandFailed {
                    command: "start_dhcp".into(),
                    message: "operation timed out".into(),
                }),
            };

            let _ = tx.send(AsyncOpResult::DhcpStarted { result });
        });
    }

    /// Stop VPN sharing (async).
    fn stop_sharing_async(&mut self) {
        if self.pending_op.is_some() {
            return; // Already busy
        }

        if self.session.is_none() {
            self.log_warning("VPN sharing is not active");
            self.state = AppState::Menu;
            return;
        }

        self.log_info("Stopping VPN sharing...");
        self.set_pending_op(PendingOp::StoppingSharing);

        let session = self.session.as_mut().unwrap();
        let dhcp_active = session.dhcp_active;
        let natpmp_active = session.natpmp_active;

        // Signal NAT-PMP server to shut down before spawning the cleanup task
        session.shutdown_natpmp();

        // Take ownership of managers for the async operation
        let (mut firewall, mut ip_forwarding) = session.take_managers();

        let tx = self.op_tx.clone();

        tokio::spawn(async move {
            let result = tokio::time::timeout(TIMEOUT_STOP_SHARING, async {
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
                    Err(crate::error::TunshareError::FirewallError(
                        errors.join("; "),
                    ))
                }
            })
            .await;

            let result = match result {
                Ok(inner) => inner,
                Err(_) => Err(crate::error::TunshareError::FirewallError(
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

    /// Fetch debug information (async).
    fn fetch_debug_info_async(&mut self) {
        if self.pending_op.is_some() {
            return; // Already busy
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
            let info = tokio::time::timeout(TIMEOUT_DEBUG_INFO, async {
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
                Err(_) => Err(crate::error::TunshareError::CommandFailed {
                    command: "fetch_debug_info".into(),
                    message: "operation timed out".into(),
                }),
            };

            let _ = tx.send(AsyncOpResult::DebugInfoFetched { info });
        });
    }

    /// Toggle debug panel visibility.
    fn toggle_debug(&mut self) {
        self.show_debug = !self.show_debug;
        if self.show_debug {
            self.fetch_debug_info_async();
        } else {
            self.debug_info = None;
        }
    }

    /// Toggle DHCP server preference (only when sharing is inactive).
    fn toggle_dhcp_preference(&mut self) {
        // Only allow toggling if dnsmasq is installed
        if !self.dnsmasq_installed {
            self.log_warning("Cannot toggle DHCP: dnsmasq not installed");
            return;
        }

        self.dhcp_enabled = !self.dhcp_enabled;
        if self.dhcp_enabled {
            self.log_info("DHCP server enabled");
        } else {
            self.log_info("DHCP server disabled (manual router config required)");
        }
    }

    /// Toggle NAT-PMP server preference (only when sharing is inactive).
    fn toggle_natpmp_preference(&mut self) {
        self.natpmp_enabled = !self.natpmp_enabled;
        if self.natpmp_enabled {
            self.log_info("NAT-PMP server enabled");
        } else {
            self.log_info("NAT-PMP server disabled");
        }
    }

    /// Start NAT-PMP server (async).
    fn start_natpmp_async(&mut self, vpn_name: String, lan_name: String, lan_ip: Ipv4Addr) {
        self.log_info("Starting NAT-PMP server...");
        self.set_pending_op(PendingOp::StartingNatPmp);

        let tx = self.op_tx.clone();

        tokio::spawn(async move {
            let lan_network = NatPmpServer::network_from_ip(lan_ip);
            let server = NatPmpServer::new(&vpn_name, &lan_name, &lan_network);

            let result = tokio::time::timeout(TIMEOUT_START_NATPMP, server.start()).await;

            let (result, server) = match result {
                Ok(inner) => {
                    let server = if inner.is_ok() { Some(server) } else { None };
                    (inner, server)
                }
                Err(_) => (
                    Err(crate::error::TunshareError::CommandFailed {
                        command: "start_natpmp".into(),
                        message: "operation timed out".into(),
                    }),
                    None,
                ),
            };

            let _ = tx.send(AsyncOpResult::NatPmpStarted { result, server });
        });
    }

    /// Handle keyboard input.
    pub fn handle_key(&mut self, key: crossterm::event::KeyCode) {
        // While an operation is pending, only allow quit and cancel
        if self.pending_op.is_some() {
            match key {
                crossterm::event::KeyCode::Char('q') => {
                    self.should_quit = true;
                }
                crossterm::event::KeyCode::Esc => {
                    self.cancel_pending_op();
                }
                _ => {}
            }
            return;
        }

        match self.state {
            AppState::Menu => self.handle_menu_key(key),
            AppState::SelectingVpn => self.handle_vpn_select_key(key),
            AppState::SelectingLan => self.handle_lan_select_key(key),
            AppState::Active => self.handle_active_key(key),
            AppState::EditingDns => self.handle_dns_edit_key(key),
        }
    }

    fn handle_menu_key(&mut self, key: crossterm::event::KeyCode) {
        use crossterm::event::KeyCode;

        let items = self.menu_items();

        match key {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.selected_menu_item > 0 {
                    self.selected_menu_item -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected_menu_item < items.len().saturating_sub(1) {
                    self.selected_menu_item += 1;
                }
            }
            KeyCode::Enter => {
                if let Some(item) = items.get(self.selected_menu_item) {
                    match item {
                        MenuItem::StartSharing => self.start_interface_selection(),
                        MenuItem::StopSharing => self.stop_sharing_async(),
                        MenuItem::ToggleDhcp => self.toggle_dhcp_preference(),
                        MenuItem::ToggleNatPmp => self.toggle_natpmp_preference(),
                        MenuItem::SetDns => self.start_dns_edit(),
                        MenuItem::Quit => self.quit(),
                    }
                }
            }
            KeyCode::Char('1') => {
                if let Some(MenuItem::StartSharing) = items.first() {
                    self.start_interface_selection();
                } else if let Some(MenuItem::StopSharing) = items.first() {
                    self.stop_sharing_async();
                }
            }
            KeyCode::Char('2') => {
                if items.len() > 1 {
                    match items[1] {
                        MenuItem::Quit => self.quit(),
                        MenuItem::StopSharing => self.stop_sharing_async(),
                        _ => {}
                    }
                }
            }
            KeyCode::Char('q') => self.quit(),
            KeyCode::Char('d') if self.is_sharing() => {
                self.toggle_debug();
            }
            KeyCode::Char('l') => {
                self.logs_expanded = !self.logs_expanded;
            }
            _ => {}
        }
    }

    fn handle_vpn_select_key(&mut self, key: crossterm::event::KeyCode) {
        use crossterm::event::KeyCode;

        match key {
            KeyCode::Up | KeyCode::Char('k') => {
                if let Some(idx) = self.selected_vpn {
                    if idx > 0 {
                        self.selected_vpn = Some(idx - 1);
                    }
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Some(idx) = self.selected_vpn {
                    if idx < self.vpn_interfaces.len().saturating_sub(1) {
                        self.selected_vpn = Some(idx + 1);
                    }
                }
            }
            KeyCode::Enter => {
                if let Some(vpn_idx) = self.selected_vpn {
                    if let Some(vpn) = self.vpn_interfaces.get(vpn_idx) {
                        // Discover DNS for selected VPN (async)
                        self.discover_dns_async(vpn.name.clone());
                    }
                }
            }
            KeyCode::Esc | KeyCode::Char('q') => {
                self.state = AppState::Menu;
                self.log_info("Cancelled interface selection");
            }
            _ => {}
        }
    }

    fn handle_lan_select_key(&mut self, key: crossterm::event::KeyCode) {
        use crossterm::event::KeyCode;

        match key {
            KeyCode::Up | KeyCode::Char('k') => {
                if let Some(idx) = self.selected_lan {
                    if idx > 0 {
                        self.selected_lan = Some(idx - 1);
                    }
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Some(idx) = self.selected_lan {
                    if idx < self.lan_interfaces.len().saturating_sub(1) {
                        self.selected_lan = Some(idx + 1);
                    }
                }
            }
            KeyCode::Enter => {
                if let Some(vpn_idx) = self.selected_vpn {
                    if let Some(lan_idx) = self.selected_lan {
                        if let (Some(vpn), Some(lan)) = (
                            self.vpn_interfaces.get(vpn_idx),
                            self.lan_interfaces.get(lan_idx),
                        ) {
                            self.start_sharing_async(
                                vpn.name.clone(),
                                lan.name.clone(),
                                lan.ipv4_address,
                            );
                        }
                    }
                }
            }
            KeyCode::Esc | KeyCode::Char('q') => {
                self.state = AppState::SelectingVpn;
                self.log_info("Back to VPN selection");
            }
            KeyCode::Backspace => {
                self.state = AppState::SelectingVpn;
                self.log_info("Back to VPN selection");
            }
            _ => {}
        }
    }

    fn handle_active_key(&mut self, key: crossterm::event::KeyCode) {
        use crossterm::event::KeyCode;

        match key {
            KeyCode::Char('s') | KeyCode::Enter => {
                self.stop_sharing_async();
            }
            KeyCode::Char('q') => {
                self.should_quit = true;
                self.stop_sharing_async();
            }
            KeyCode::Char('d') => {
                self.toggle_debug();
            }
            KeyCode::Char('l') => {
                self.logs_expanded = !self.logs_expanded;
            }
            KeyCode::Esc => {
                if self.show_debug {
                    self.show_debug = false;
                    self.debug_info = None;
                } else {
                    self.state = AppState::Menu;
                }
            }
            _ => {}
        }
    }

    /// Start editing DNS.
    fn start_dns_edit(&mut self) {
        self.dns.input_buffer = self.dns.custom.clone().unwrap_or_default();
        self.dns.edit_mode = DnsEditMode::SelectingPreset;
        // Pre-select current DNS in the preset list
        self.dns.preset_selected = if self.dns.custom.is_none() {
            0 // Auto-detect
        } else if let Some(ref dns) = self.dns.custom {
            // Check if the custom DNS matches a preset
            DNS_PRESETS
                .iter()
                .position(|p| p.ip == dns.as_str())
                .map(|i| i + 1) // +1 because 0 is Auto-detect
                .unwrap_or(DNS_PRESETS.len() + 1) // Custom...
        } else {
            0
        };
        self.state = AppState::EditingDns;
    }

    /// Handle key input during DNS editing (dispatches by mode).
    fn handle_dns_edit_key(&mut self, key: crossterm::event::KeyCode) {
        match self.dns.edit_mode {
            DnsEditMode::SelectingPreset => self.handle_dns_preset_key(key),
            DnsEditMode::CustomInput => self.handle_dns_custom_input_key(key),
        }
    }

    /// Total number of items in the preset list (Auto-detect + presets + Custom...).
    fn dns_preset_count(&self) -> usize {
        1 + DNS_PRESETS.len() + 1
    }

    /// Handle key input in preset selection mode.
    fn handle_dns_preset_key(&mut self, key: crossterm::event::KeyCode) {
        use crossterm::event::KeyCode;

        let count = self.dns_preset_count();
        match key {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.dns.preset_selected > 0 {
                    self.dns.preset_selected -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.dns.preset_selected < count - 1 {
                    self.dns.preset_selected += 1;
                }
            }
            KeyCode::Enter => {
                let idx = self.dns.preset_selected;
                if idx == 0 {
                    // Auto-detect
                    self.dns.custom = None;
                    self.log_info("DNS reset to auto-detect");
                    self.state = AppState::Menu;
                } else if idx <= DNS_PRESETS.len() {
                    // A preset
                    let preset = &DNS_PRESETS[idx - 1];
                    self.dns.custom = Some(preset.ip.to_string());
                    self.log_success(format!("DNS set to {} ({})", preset.ip, preset.name));
                    self.state = AppState::Menu;
                } else {
                    // Custom...
                    self.dns.edit_mode = DnsEditMode::CustomInput;
                    self.dns.input_buffer = self.dns.custom.clone().unwrap_or_default();
                }
            }
            KeyCode::Esc => {
                self.dns.input_buffer.clear();
                self.state = AppState::Menu;
            }
            _ => {}
        }
    }

    /// Handle key input in custom DNS input mode.
    fn handle_dns_custom_input_key(&mut self, key: crossterm::event::KeyCode) {
        use crossterm::event::KeyCode;

        match key {
            KeyCode::Char(c) => {
                // Only allow digits, dots, and colons (for IPv6)
                if c.is_ascii_digit() || c == '.' || c == ':' {
                    self.dns.input_buffer.push(c);
                }
            }
            KeyCode::Backspace => {
                self.dns.input_buffer.pop();
            }
            KeyCode::Enter => {
                let input = self.dns.input_buffer.trim().to_string();
                if input.is_empty() {
                    self.dns.custom = None;
                    self.log_info("DNS reset to auto-detect");
                } else if input.parse::<IpAddr>().is_ok() {
                    self.dns.custom = Some(input.clone());
                    self.log_success(format!("Custom DNS set to {}", input));
                } else {
                    self.log_warning(format!("Invalid IP address: {}", input));
                }
                self.dns.input_buffer.clear();
                self.state = AppState::Menu;
            }
            KeyCode::Esc => {
                // Go back to preset list
                self.dns.edit_mode = DnsEditMode::SelectingPreset;
            }
            _ => {}
        }
    }

    /// Start the interface selection flow.
    fn start_interface_selection(&mut self) {
        self.refresh_interfaces_async();
    }

    /// Quit the application.
    fn quit(&mut self) {
        if self.is_sharing() {
            self.should_quit = true;
            self.stop_sharing_async();
        } else {
            self.should_quit = true;
        }
    }

    /// Get the help text for current state.
    pub fn help_text(&self) -> &'static str {
        if self.pending_op.is_some() {
            return "Esc: Cancel  q: Force quit";
        }

        match self.state {
            AppState::Menu if self.is_sharing() => {
                "↑/↓: Navigate  Enter: Select  d: Debug  l: Logs  q: Quit"
            }
            AppState::Menu => "↑/↓: Navigate  Enter: Select  l: Logs  q: Quit",
            AppState::SelectingVpn => "↑/↓: Navigate  Enter: Select  Esc: Cancel",
            AppState::SelectingLan => "↑/↓: Navigate  Enter: Select  ←: Back  Esc: Cancel",
            AppState::Active if self.show_debug => "d: Hide debug  s: Stop  l: Logs  q: Quit",
            AppState::Active => "s: Stop  d: Debug  l: Logs  q: Quit",
            AppState::EditingDns => match self.dns.edit_mode {
                DnsEditMode::SelectingPreset => "↑/↓: Navigate  Enter: Select  Esc: Cancel",
                DnsEditMode::CustomInput => "Enter: Save  Esc: Back  (empty = auto-detect)",
            },
        }
    }

    // Logging helpers

    /// Append a log entry, evicting the oldest if at capacity.
    fn push_log(&mut self, entry: LogEntry) {
        if self.logs.len() >= MAX_LOG_ENTRIES {
            self.logs.pop_front();
        }
        self.logs.push_back(entry);
    }

    fn log_info(&mut self, msg: impl Into<String>) {
        self.push_log(LogEntry::info(msg));
    }

    fn log_success(&mut self, msg: impl Into<String>) {
        self.push_log(LogEntry::success(msg));
    }

    fn log_warning(&mut self, msg: impl Into<String>) {
        self.push_log(LogEntry::warning(msg));
    }

    fn log_error(&mut self, msg: impl Into<String>) {
        self.push_log(LogEntry::error(msg));
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for App {
    fn drop(&mut self) {
        // SharingSession::drop handles all cleanup in the correct order.
        // Dropping `self.session` triggers it automatically.
        drop(self.session.take());
    }
}
