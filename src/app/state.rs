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
    Doctor,
    /// Modal asking the user to install dnsmasq via Homebrew.
    InstallDnsmasq,
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
            vec![MenuItem::StopSharing, MenuItem::Quit]
        } else {
            vec![
                MenuItem::StartSharing,
                MenuItem::ToggleDhcp,
                MenuItem::ToggleNatPmp,
                MenuItem::SetDns,
                MenuItem::RunDoctor,
                MenuItem::Quit,
            ]
        }
    }

    /// Whether a menu item is non-interactive in the current state. Disabled
    /// items render dimmed and are skipped by keyboard navigation.
    ///
    /// Note: items the user can't currently *act* on but can still navigate to
    /// (e.g. DHCP when dnsmasq isn't installed — they should still be able to
    /// read the description that tells them how to fix it) are not disabled
    /// here. The Enter handler decides whether the action runs.
    pub fn is_menu_item_disabled(&self, _item: &MenuItem) -> bool {
        false
    }

    /// Find the next enabled menu index in `direction` (+1 down, -1 up),
    /// starting from `from`. Returns `from` if no enabled item exists in that
    /// direction (caller stays put — acts like a clamp).
    pub(super) fn next_enabled_menu_index(&self, from: usize, direction: i32) -> usize {
        let items = self.menu_items();
        let len = items.len() as i32;
        let mut i = from as i32 + direction;
        while i >= 0 && i < len {
            if !self.is_menu_item_disabled(&items[i as usize]) {
                return i as usize;
            }
            i += direction;
        }
        from
    }
}
