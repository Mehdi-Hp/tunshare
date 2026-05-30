//! Tunnel MTU configuration, presets, and edit-mode state.

use crate::config::LanMtu;

/// A row in the MTU preset picker.
///
/// `Auto` measures the real path MTU with an active probe each time sharing
/// starts (tracking tunnel changes across reconnects); the `Fixed` rows pin a
/// known tunnel MTU. Either way the pf scrub clamp is `MTU - 40`.
#[derive(Debug, Clone, Copy)]
pub enum Preset {
    Auto,
    Fixed(u16, &'static str),
    Custom,
}

/// Built-in preset rows, in the order shown in the picker.
pub const PRESETS: &[Preset] = &[
    Preset::Auto,
    Preset::Fixed(1500, "Ethernet"),
    Preset::Fixed(1492, "PPPoE"),
    Preset::Fixed(1420, "WireGuard"),
    Preset::Fixed(1400, "OpenVPN"),
    Preset::Custom,
];

/// Index of the `Custom...` row, used by input handling to switch sub-mode.
pub const CUSTOM_INPUT_IDX: usize = PRESETS.len() - 1;

/// MTU edit sub-mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MtuEditMode {
    SelectingPreset,
    CustomInput,
}

/// Tunnel MTU configuration and edit state.
pub struct MtuConfig {
    /// Active policy (mirrors `Config::lan_mtu`).
    pub active: LanMtu,
    /// Text input buffer for the Custom sub-mode.
    pub input_buffer: String,
    /// Current sub-mode (preset list vs custom input).
    pub edit_mode: MtuEditMode,
    /// Highlighted row index into [`PRESETS`].
    pub preset_selected: usize,
}

impl MtuConfig {
    pub fn new(active: LanMtu) -> Self {
        let preset_selected = match active {
            LanMtu::Auto => 0,
            LanMtu::Fixed(n) => PRESETS
                .iter()
                .position(|p| matches!(p, Preset::Fixed(v, _) if *v == n))
                .unwrap_or(CUSTOM_INPUT_IDX),
        };
        Self {
            active,
            input_buffer: String::new(),
            edit_mode: MtuEditMode::SelectingPreset,
            preset_selected,
        }
    }

    /// Short human-readable label for the active policy. Used in the menu row.
    pub fn active_label(&self) -> String {
        match self.active {
            LanMtu::Auto => "Auto".to_string(),
            LanMtu::Fixed(n) => n.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preset_selected_round_trips_fixed_presets() {
        assert_eq!(MtuConfig::new(LanMtu::Auto).preset_selected, 0);
        // 1420 (WireGuard) is at index 3 in PRESETS.
        assert_eq!(MtuConfig::new(LanMtu::Fixed(1420)).preset_selected, 3);
    }

    #[test]
    fn unknown_fixed_value_falls_back_to_custom_row() {
        // 1337 isn't in the preset list — should land on the Custom row.
        assert_eq!(
            MtuConfig::new(LanMtu::Fixed(1337)).preset_selected,
            CUSTOM_INPUT_IDX
        );
    }

    #[test]
    fn active_label_for_each_variant() {
        assert_eq!(MtuConfig::new(LanMtu::Auto).active_label(), "Auto");
        assert_eq!(MtuConfig::new(LanMtu::Fixed(1420)).active_label(), "1420");
    }
}
