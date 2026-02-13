//! Centralized theme definitions for the TUI.
//!
//! Inspired by lazygit, k9s, and bottom terminal applications.

/// Border character set for rounded boxes.
pub mod borders {
    pub const TOP_LEFT: &str = "\u{256d}"; // ╭
    pub const TOP_RIGHT: &str = "\u{256e}"; // ╮
    pub const BOTTOM_LEFT: &str = "\u{2570}"; // ╰
    pub const BOTTOM_RIGHT: &str = "\u{256f}"; // ╯
    pub const HORIZONTAL: &str = "\u{2500}"; // ─
    pub const VERTICAL: &str = "\u{2502}"; // │
}

/// Unicode symbols used throughout the UI.
pub mod symbols {
    pub const APP_ICON: &str = "\u{25c9}"; // ◉
    pub const STATUS_ACTIVE: &str = "\u{25cf}"; // ●
    pub const STATUS_INACTIVE: &str = "\u{25cb}"; // ○
    pub const SELECTED: &str = "\u{25b6}"; // ▶
    pub const WARNING: &str = "\u{26a0}"; // ⚠
    pub const ERROR: &str = "\u{2717}"; // ✗
    pub const TREE_BRANCH: &str = "\u{251c}\u{2500}"; // ├─
    pub const TREE_END: &str = "\u{2514}\u{2500}"; // └─
    pub const ARROW_RIGHT: &str = "\u{2500}\u{2500}\u{2500}\u{2500}\u{25b6}"; // ────▶
    pub const SEPARATOR_CHAR: &str = "\u{254c}"; // ╌

    /// Moon phase spinner characters for loading animations.
    pub const MOON_SPINNER: &[char] = &['\u{25d0}', '\u{25d3}', '\u{25d1}', '\u{25d2}'];
    // ◐◓◑◒
}

/// Color palette for the application.
pub mod colors {
    use ratatui::style::Color;

    /// Default border color (inactive).
    pub const BORDER_DEFAULT: Color = Color::Gray;
    /// Focused/active border color.
    pub const BORDER_FOCUS: Color = Color::Cyan;

    /// Primary text color.
    pub const TEXT_PRIMARY: Color = Color::White;
    /// Secondary/muted text color.
    pub const TEXT_SECONDARY: Color = Color::DarkGray;

    /// Success/active status color.
    pub const SUCCESS: Color = Color::Green;
    /// Warning color.
    pub const WARNING: Color = Color::Yellow;
    /// Error color.
    pub const ERROR: Color = Color::Red;
    /// Accent color (title, spinners, info).
    pub const ACCENT: Color = Color::Cyan;
    /// LAN interface indicator color.
    pub const LAN: Color = Color::Blue;
}

/// Pre-defined styles for common UI elements.
pub mod styles {
    use super::colors;
    use ratatui::style::{Modifier, Style};

    /// Style for the app title.
    pub fn title() -> Style {
        Style::default()
            .fg(colors::ACCENT)
            .add_modifier(Modifier::BOLD)
    }

    /// Style for active status badge.
    pub fn status_active() -> Style {
        Style::default()
            .fg(colors::SUCCESS)
            .add_modifier(Modifier::BOLD)
    }

    /// Style for inactive status badge.
    pub fn status_inactive() -> Style {
        Style::default().fg(colors::TEXT_SECONDARY)
    }

    /// Style for selected/highlighted items.
    pub fn selected() -> Style {
        Style::default()
            .fg(colors::WARNING)
            .add_modifier(Modifier::BOLD)
    }

    /// Style for unselected items.
    pub fn unselected() -> Style {
        Style::default().fg(colors::TEXT_PRIMARY)
    }

    /// Style for focused border.
    pub fn border_focused() -> Style {
        Style::default().fg(colors::BORDER_FOCUS)
    }

    /// Style for unfocused border.
    pub fn border_unfocused() -> Style {
        Style::default().fg(colors::BORDER_DEFAULT)
    }

    /// Style for help text.
    pub fn help_text() -> Style {
        Style::default().fg(colors::TEXT_SECONDARY)
    }

    /// Style for key hints in help bar.
    pub fn help_key() -> Style {
        Style::default()
            .fg(colors::ACCENT)
            .add_modifier(Modifier::BOLD)
    }

    /// Style for step indicator text.
    pub fn step_indicator() -> Style {
        Style::default()
            .fg(colors::TEXT_PRIMARY)
            .add_modifier(Modifier::BOLD)
    }

    /// Style for VPN interface text.
    pub fn vpn_interface() -> Style {
        Style::default().fg(colors::SUCCESS)
    }

    /// Style for LAN interface text.
    pub fn lan_interface() -> Style {
        Style::default().fg(colors::LAN)
    }

    /// Style for tree branch characters.
    pub fn tree_branch() -> Style {
        Style::default().fg(colors::TEXT_SECONDARY)
    }

    /// Style for card title.
    pub fn card_title() -> Style {
        Style::default()
            .fg(colors::TEXT_SECONDARY)
            .add_modifier(Modifier::BOLD)
    }

    /// Style for hint/secondary text below items.
    pub fn hint() -> Style {
        Style::default().fg(colors::TEXT_SECONDARY)
    }

    /// Style for ON status badge.
    pub fn status_on() -> Style {
        Style::default().fg(colors::SUCCESS)
    }

    /// Style for OFF status badge.
    pub fn status_off() -> Style {
        Style::default().fg(colors::TEXT_SECONDARY)
    }

    /// Style for degraded status badge (connection warning).
    pub fn status_degraded() -> Style {
        Style::default()
            .fg(colors::WARNING)
            .add_modifier(Modifier::BOLD)
    }

    /// Style for down status badge (connection lost).
    pub fn status_down() -> Style {
        Style::default()
            .fg(colors::ERROR)
            .add_modifier(Modifier::BOLD)
    }

    /// Style for separator lines.
    pub fn separator() -> Style {
        Style::default().fg(colors::TEXT_SECONDARY)
    }
}
