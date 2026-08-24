//! Application state and message handling (Elm architecture) with async support.
//!
//! The `App` struct is the single owner of all UI state. Methods live in the
//! submodules below, split by concern so each file stays under ~500 lines:
//!
//! - [`state`]      pure state types: `AppState`, `MenuItem`, `DoctorState`
//! - [`dns`]        DNS presets/history/picker indexing
//! - [`log`]        in-app log buffer (`LogEntry` + `log_*` helpers)
//! - [`async_ops`]  every `tokio::spawn` plus `AsyncOpResult`/`PendingOp`/`DebugInfo`
//! - [`result`]     `handle_async_result` dispatch + per-result handlers + health
//! - [`input`]      keyboard input dispatch and per-screen handlers
//!
//! External callers (UI rendering, `main.rs`) import from this module via
//! the re-exports at the bottom of this file.

mod async_ops;
mod dns;
mod input;
mod log;
pub mod mtu;
mod result;
mod state;
pub mod traffic;

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use crate::config::{Config, ListsConfig};
use crate::health::{HealthStatus, VpnDropStrategy};
use crate::session::SharingSession;
use crate::system::{DhcpServer, InterfaceInfo};

pub use async_ops::{AsyncOpResult, DebugInfo, PendingOp};
pub use dns::{DnsConfig, DnsEditMode, DNS_PRESETS};
pub use log::LogEntry;
pub use mtu::MtuConfig;
pub use state::{AppState, DoctorState, FilterJob, FilterRow, MenuItem};

/// Application state.
pub struct App {
    pub vpn_interfaces: Vec<InterfaceInfo>,
    pub lan_interfaces: Vec<InterfaceInfo>,
    pub dns: DnsConfig,
    pub mtu: MtuConfig,
    pub selected_vpn: Option<usize>,
    pub selected_lan: Option<usize>,
    pub session: Option<SharingSession>,
    pub logs: VecDeque<LogEntry>,
    pub state: AppState,
    pub selected_menu_item: usize,
    pub should_quit: bool,

    /// Channel sender for async operation results. Cloned into each spawn.
    pub(super) op_tx: mpsc::UnboundedSender<AsyncOpResult>,
    /// Channel receiver, drained by `poll_async_results`.
    op_rx: mpsc::UnboundedReceiver<AsyncOpResult>,

    pub pending_op: Option<PendingOp>,
    pub pending_op_started: Option<Instant>,
    pub show_debug: bool,
    pub debug_info: Option<DebugInfo>,
    pub logs_expanded: bool,
    pub dhcp_enabled: bool,
    pub natpmp_enabled: bool,
    pub dnsmasq_installed: bool,
    /// Snapshot of `brew_installed()` taken when the InstallDnsmasq modal
    /// opens. Rendered each frame, so we cache instead of shelling out per
    /// draw call. Refreshed every time the modal is entered.
    pub brew_installed: bool,

    /// Next scheduled health check time (None when not sharing).
    pub(super) next_health_check: Option<Instant>,
    /// Next scheduled traffic sample time (None when not sharing).
    pub(super) next_traffic_sample: Option<Instant>,
    pub vpn_drop_strategy: VpnDropStrategy,
    pub doctor: DoctorState,
    /// Where Esc should return to when leaving the Doctor screen. `None`
    /// (the default) routes to `Menu`; set when the user enters Doctor
    /// from a state we want to restore (e.g. `PreflightBlocked`).
    pub(super) doctor_return_state: Option<AppState>,
    /// Block/allow list toggles and cached counts.
    pub lists: ListsConfig,
    pub lists_ui: ListsUi,
}

/// TUI snapshot for the Domain filters screen. Counts come from the last fetch.
#[derive(Debug, Clone)]
pub struct ListsUi {
    /// Which column owns ↑/↓ and Enter.
    pub focus: FilterJob,
    pub block_selected: usize,
    pub allow_selected: usize,
    pub block_count: usize,
    pub allow_count: usize,
    pub block_fetched: Option<std::time::SystemTime>,
    pub allow_fetched: Option<std::time::SystemTime>,
    /// Where Esc should return (`Menu` or `Active`).
    pub return_state: AppState,
    /// URL overlay for **Add source…**. `None` = browsing rows.
    pub adding: Option<FilterJob>,
    pub input_buffer: String,
}

impl Default for ListsUi {
    fn default() -> Self {
        Self {
            focus: FilterJob::Block,
            block_selected: 0,
            allow_selected: 0,
            block_count: 0,
            allow_count: 0,
            block_fetched: None,
            allow_fetched: None,
            return_state: AppState::Menu,
            adding: None,
            input_buffer: String::new(),
        }
    }
}

impl App {
    /// Create a new application instance.
    pub fn new() -> Self {
        let (op_tx, op_rx) = mpsc::unbounded_channel();

        let config = Config::load();
        let dnsmasq_available = DhcpServer::is_dnsmasq_installed();

        let mut app = Self {
            vpn_interfaces: Vec::new(),
            lan_interfaces: Vec::new(),
            dns: DnsConfig::new(config.custom_dns, config.dns_history),
            mtu: MtuConfig::new(config.lan_mtu),
            selected_vpn: None,
            selected_lan: None,
            session: None,
            logs: VecDeque::with_capacity(log::MAX_LOG_ENTRIES),
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
            dhcp_enabled: config.dhcp_enabled && dnsmasq_available,
            natpmp_enabled: config.natpmp_enabled,
            dnsmasq_installed: dnsmasq_available,
            brew_installed: false,
            next_health_check: None,
            next_traffic_sample: None,
            vpn_drop_strategy: config.vpn_drop_strategy,
            doctor: DoctorState::default(),
            doctor_return_state: None,
            lists: config.lists.clone(),
            lists_ui: ListsUi {
                return_state: AppState::Menu,
                ..ListsUi::default()
            },
        };

        app.log_info("Ready. Press Enter to start VPN sharing.");
        if !dnsmasq_available {
            app.log_warning("dnsmasq not found. Install with: brew install dnsmasq");
            app.log_info("DHCP will be disabled; router needs manual IP config.");
        }
        app
    }

    // ===== Status accessors (used by UI rendering) =====

    pub fn is_sharing(&self) -> bool {
        self.session.is_some()
    }

    pub fn dhcp_active(&self) -> bool {
        self.session.as_ref().is_some_and(|s| s.dhcp_active)
    }

    pub fn natpmp_active(&self) -> bool {
        self.session.as_ref().is_some_and(|s| s.natpmp_active)
    }

    pub fn dhcp_range(&self) -> Option<&(String, String)> {
        self.session.as_ref().and_then(|s| s.dhcp_range.as_ref())
    }

    /// Connection health status (Healthy if not sharing).
    pub fn health_status(&self) -> &HealthStatus {
        static HEALTHY: HealthStatus = HealthStatus::Healthy;
        self.session
            .as_ref()
            .map(|s| &s.health_status)
            .unwrap_or(&HEALTHY)
    }

    /// Seconds remaining before auto-stop fires while VPN is down.
    ///
    /// Returns `None` when the strategy doesn't auto-stop (Ignore), when
    /// the session isn't degraded, or when no session is active.
    /// Returns `Some(0)` when the wait window has elapsed (stop is imminent).
    pub fn vpn_drop_countdown_secs(&self) -> Option<u64> {
        let session = self.session.as_ref()?;
        if !matches!(session.health_status, HealthStatus::Down(_)) {
            return None;
        }
        let wait = self.vpn_drop_strategy.wait_duration()?;
        let since = session.degraded_since?;
        Some(wait.saturating_sub(since.elapsed()).as_secs())
    }

    /// Elapsed time since the pending operation started.
    pub fn pending_elapsed(&self) -> Option<Duration> {
        self.pending_op_started.map(|start| start.elapsed())
    }

    // ===== Pending-op bookkeeping (used by async_ops + result) =====

    pub(super) fn set_pending_op(&mut self, op: PendingOp) {
        self.pending_op = Some(op);
        self.pending_op_started = Some(Instant::now());
    }

    pub(super) fn clear_pending_op(&mut self) {
        self.pending_op = None;
        self.pending_op_started = None;
    }

    // ===== Main loop hook =====

    /// Drain the async result channel and schedule periodic health checks.
    /// Called once per frame by the main event loop.
    pub fn poll_async_results(&mut self) {
        while let Ok(result) = self.op_rx.try_recv() {
            self.handle_async_result(result);
        }

        if self.is_sharing() && self.pending_op.is_none() {
            let now = Instant::now();
            if let Some(next) = self.next_health_check {
                if now >= next {
                    self.spawn_health_check();
                }
            }
            if let Some(next) = self.next_traffic_sample {
                if now >= next {
                    self.spawn_traffic_sample();
                }
            }
        }
    }

    // ===== Help bar =====

    /// Help text for the current state. Rendered in the bottom status bar.
    pub fn help_text(&self) -> &'static str {
        if self.pending_op.is_some() {
            return "Esc: Cancel  q: Force quit";
        }

        match self.state {
            AppState::Menu if self.is_sharing() => {
                "↑/↓: Navigate  Enter: Select  d: Debug  l: Domain filters  q: Quit"
            }
            AppState::Menu => "↑/↓: Navigate  Enter: Select  l: Logs  q: Quit",
            AppState::SelectingVpn => "↑/↓: Navigate  Enter: Select  Esc: Cancel",
            AppState::SelectingLan => "↑/↓: Navigate  Enter: Select  ←: Back  Esc: Cancel",
            AppState::Active if self.show_debug => "d: Hide debug  s: Stop  l: Logs  q: Quit",
            AppState::Active => "s: Stop  d: Debug  l: Domain filters  q: Quit",
            AppState::Doctor if self.doctor_has_stale_anchor() => {
                "↑/↓: Navigate  r: Re-run  c: Clean stale anchor  Esc: Back"
            }
            AppState::Doctor => "↑/↓: Navigate  r: Re-run  Esc: Back",
            AppState::InstallDnsmasq if self.brew_installed => "Enter: Install  Esc: Cancel",
            AppState::InstallDnsmasq => "Esc: Dismiss",
            AppState::PreflightBlocked => "r: Rescan  d: Doctor  Esc: Cancel",
            AppState::ViewingLists if self.lists_ui.adding.is_some() => {
                "Enter: Add  Esc: Back  (https://…)"
            }
            AppState::ViewingLists => {
                "↑/↓: Navigate  Tab/←→: Column  Enter: Toggle  x: Remove  r: Refresh  Esc: Back"
            }
            AppState::EditingDns => match self.dns.edit_mode {
                DnsEditMode::SelectingPreset if !self.dns.history.is_empty() => {
                    "↑/↓: Navigate  Enter: Select  x: Remove recent  Esc: Cancel"
                }
                DnsEditMode::SelectingPreset => "↑/↓: Navigate  Enter: Select  Esc: Cancel",
                DnsEditMode::CustomInput => "Enter: Save  Esc: Back  (empty = auto-detect)",
            },
            AppState::EditingMtu => match self.mtu.edit_mode {
                mtu::MtuEditMode::SelectingPreset => "↑/↓: Navigate  Enter: Select  Esc: Cancel",
                mtu::MtuEditMode::CustomInput => "Enter: Save  Esc: Back  (576–9000 bytes)",
            },
        }
    }

    // ===== Persistence =====

    /// Save current preferences to config file.
    pub(super) fn save_preferences(&self) {
        Config {
            dhcp_enabled: self.dhcp_enabled,
            natpmp_enabled: self.natpmp_enabled,
            custom_dns: self.dns.custom.clone(),
            dns_history: self.dns.history.clone(),
            vpn_drop_strategy: self.vpn_drop_strategy,
            lan_mtu: self.mtu.active,
            lists: self.lists.clone(),
        }
        .save();
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn initial_state_is_menu_and_not_quitting() {
        let app = App::new();
        assert_eq!(app.state, AppState::Menu);
        assert_eq!(app.selected_menu_item, 0);
        assert!(!app.should_quit);
        assert!(app.session.is_none());
    }

    #[test]
    fn vpn_drop_countdown_only_set_when_session_down() {
        let mut app = App::new();
        // No session → countdown is None.
        assert!(app.vpn_drop_countdown_secs().is_none());

        // Attach a minimal session; manually set Down state.
        app.session = Some(SharingSession::new(
            crate::system::Firewall::new(),
            crate::system::IpForwarding::new(),
            crate::session::ActiveUpstream {
                name: "utun4".to_string(),
                link_mtu: 1500,
                effective_mtu: 1400,
            },
            "en0".to_string(),
            Ipv4Addr::new(192, 168, 2, 1),
        ));

        // Healthy session → no countdown.
        assert!(app.vpn_drop_countdown_secs().is_none());

        // Set Down with degraded_since 5s ago + 15s strategy → ~10s remaining.
        if let Some(ref mut s) = app.session {
            s.health_status = HealthStatus::Down("test".to_string());
            s.degraded_since = Some(Instant::now() - Duration::from_secs(5));
        }
        app.vpn_drop_strategy = VpnDropStrategy::WaitWithTimeout { timeout_secs: 15 };
        let remaining = app.vpn_drop_countdown_secs().expect("countdown set");
        assert!(
            (9..=10).contains(&remaining),
            "expected ~10s remaining, got {remaining}"
        );

        // Ignore strategy → no countdown even when Down.
        app.vpn_drop_strategy = VpnDropStrategy::Ignore;
        assert!(app.vpn_drop_countdown_secs().is_none());
    }
}
