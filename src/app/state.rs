//! Pure UI state types (no behavior): screen state, menu layout, doctor.

use crate::doctor::CheckResult;

use super::App;

/// Current UI state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppState {
    Menu,
    SelectingVpn,
    SelectingLan,
    Active,
    EditingDns,
    EditingMtu,
    Doctor,
    /// Modal asking the user to install dnsmasq via Homebrew.
    InstallDnsmasq,
    /// Modal shown after detection completes with at least one missing
    /// prerequisite (no VPN, no wired LAN, or both).
    PreflightBlocked,
    /// Blocklist / allowlist toggles, counts, and refresh.
    ViewingLists,
}

/// Menu items. The actual list shown depends on whether sharing is active —
/// see [`App::menu_items`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuItem {
    StartSharing,
    StopSharing,
    ToggleDhcp,
    ToggleNatPmp,
    SetDns,
    SetMtu,
    ViewLists,
    RunDoctor,
    Quit,
}

/// In-app Doctor screen state.
#[derive(Debug, Default)]
pub struct DoctorState {
    /// Most recent check results (empty while running or before first run).
    pub results: Vec<CheckResult>,
    /// Cursor position in the result list (counts only result rows, not
    /// group headers — those are skipped during navigation).
    pub selected: usize,
}

impl App {
    /// Menu items for the current sharing state.
    pub fn menu_items(&self) -> Vec<MenuItem> {
        if self.is_sharing() {
            vec![MenuItem::StopSharing, MenuItem::ViewLists, MenuItem::Quit]
        } else {
            vec![
                MenuItem::StartSharing,
                MenuItem::ToggleDhcp,
                MenuItem::ToggleNatPmp,
                MenuItem::SetDns,
                MenuItem::SetMtu,
                MenuItem::ViewLists,
                MenuItem::RunDoctor,
                MenuItem::Quit,
            ]
        }
    }
}
