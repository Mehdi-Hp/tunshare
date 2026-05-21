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
    pub fn is_menu_item_disabled(&self, item: &MenuItem) -> bool {
        matches!(item, MenuItem::ToggleDhcp if !self.dnsmasq_installed)
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
