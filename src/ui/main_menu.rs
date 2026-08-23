//! Main menu and header rendering.

use ratatui::{
    layout::{Alignment, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Clear, Paragraph},
    Frame,
};

use crate::app::mtu::{MtuEditMode, Preset as MtuPreset, PRESETS as MTU_PRESETS};
use crate::app::traffic::{format_bytes, format_rate, TrafficStats};
use crate::app::{App, AppState, DnsEditMode, MenuItem, DNS_PRESETS};
use crate::health::HealthStatus;
use crate::ui::theme::{borders, colors, styles, symbols};
use crate::ui::widgets::Card;

/// Render the single-line header with app title and status badge.
pub fn render_header(frame: &mut Frame, area: Rect, app: &App) {
    let (status_text, status_style, status_icon) = if app.is_sharing() {
        match app.health_status() {
            HealthStatus::Healthy => (
                "Active".to_string(),
                styles::status_active(),
                symbols::STATUS_ACTIVE,
            ),
            HealthStatus::Degraded(_) => (
                "Degraded".to_string(),
                styles::status_degraded(),
                symbols::WARNING,
            ),
            HealthStatus::Down(_) => {
                let text = match app.vpn_drop_countdown_secs() {
                    Some(0) => "VPN Down · stopping".to_string(),
                    Some(secs) => format!("VPN Down · auto-stop in {secs}s"),
                    None => "VPN Down".to_string(),
                };
                (text, styles::status_down(), symbols::ERROR)
            }
        }
    } else {
        let text = match app.state {
            AppState::SelectingVpn
            | AppState::SelectingLan
            | AppState::EditingDns
            | AppState::EditingMtu => "Configuring",
            _ => "Inactive",
        };
        (
            text.to_string(),
            styles::status_inactive(),
            symbols::STATUS_INACTIVE,
        )
    };

    // Build the header line
    let title = Span::styled(format!("{} VPN Share", symbols::APP_ICON), styles::title());

    let status = Span::styled(format!("{} {}", status_icon, status_text), status_style);

    // Calculate spacing
    let title_width = title.content.chars().count();
    let status_width = status.content.chars().count();
    let spacing = (area.width as usize)
        .saturating_sub(title_width)
        .saturating_sub(status_width);

    let header_line = Line::from(vec![title, Span::raw(" ".repeat(spacing.max(1))), status]);

    let header = Paragraph::new(header_line);
    frame.render_widget(header, area);
}

/// Render the separator line below header.
pub fn render_separator(frame: &mut Frame, area: Rect) {
    let mut line = String::new();
    for _ in 0..area.width {
        line.push_str(borders::HORIZONTAL);
    }
    let sep = Paragraph::new(Line::from(Span::styled(line, styles::border_unfocused())));
    frame.render_widget(sep, area);
}

/// Status badge for menu items.
enum StatusBadge {
    On,
    Off,
    Value(String),
    Disabled(String),
}

/// Render the main menu with centered card.
pub fn render_main_menu(frame: &mut Frame, area: Rect, app: &App) {
    let items = app.menu_items();

    // Split items into groups for visual separation
    let mut group_action: Vec<(usize, &MenuItem)> = Vec::new();
    let mut group_settings: Vec<(usize, &MenuItem)> = Vec::new();
    let mut group_quit: Vec<(usize, &MenuItem)> = Vec::new();

    for (i, item) in items.iter().enumerate() {
        match item {
            MenuItem::StartSharing | MenuItem::StopSharing => group_action.push((i, item)),
            MenuItem::ToggleDhcp
            | MenuItem::ToggleNatPmp
            | MenuItem::SetDns
            | MenuItem::SetMtu
            | MenuItem::ViewLists
            | MenuItem::RunDoctor => group_settings.push((i, item)),
            MenuItem::Quit => group_quit.push((i, item)),
        }
    }

    // Build list of "rows" with group separators
    // Each group: blank, items, blank, separator
    // Layout: blank, action items, blank, sep, blank, settings items, blank, sep, blank, quit, blank
    let mut rows: Vec<MenuRow> = Vec::new();

    // Group 1: action
    rows.push(MenuRow::Blank);
    for &(i, item) in &group_action {
        rows.push(MenuRow::Item(i, item));
    }
    rows.push(MenuRow::Blank);

    // Separator between action and next group
    let has_settings = !group_settings.is_empty();
    if has_settings {
        rows.push(MenuRow::Separator);
        rows.push(MenuRow::Blank);
        for &(i, item) in &group_settings {
            rows.push(MenuRow::Item(i, item));
        }
        rows.push(MenuRow::Blank);
    }

    // Separator before quit
    if !group_quit.is_empty() {
        rows.push(MenuRow::Separator);
        rows.push(MenuRow::Blank);
        for &(i, item) in &group_quit {
            rows.push(MenuRow::Item(i, item));
        }
        rows.push(MenuRow::Blank);
    }

    // Calculate card dimensions. Width must accommodate the widest
    // label + badge pair plus the selection prefix and at least 4 cells of
    // breathing room between them, otherwise the right-aligned badge will
    // collide with the label (see `render_menu_item`'s gap math).
    const PREFIX_WIDTH: u16 = 5;
    const MIN_GAP: u16 = 4;
    let widest_row = items
        .iter()
        .map(|item| {
            let (label, status) = menu_item_label_status(item, app);
            let label_w = label.chars().count() as u16;
            let badge_w = status.as_ref().map(badge_width).unwrap_or(0);
            PREFIX_WIDTH + label_w + MIN_GAP + badge_w
        })
        .max()
        .unwrap_or(42);
    let card_content_width = widest_row.max(60).min(area.width.saturating_sub(2));
    let card_content_height = rows.len() as u16;
    let card_width = (card_content_width + 2).min(area.width);
    let card_height = card_content_height + 2;

    // Description block for the selected item: blank + title + 1-3 body lines.
    // Width matches the card so the block reads as a unit.
    let desc_width = card_width;
    let selected_item = items.get(app.selected_menu_item);
    let desc = selected_item.map(|item| menu_item_description(item, app));
    // Reserve a fixed body height (max across all items) so the card doesn't
    // shift vertically when the selected item's description has fewer lines.
    const DESC_BODY_RESERVED: u16 = 3;
    // Layout below card: blank, title, body lines, blank, hint
    let desc_block_height = if desc.is_some() {
        1 + 1 + DESC_BODY_RESERVED + 1 + 1
    } else {
        0
    };

    // Total block = card + description + hint. Center vertically together.
    let total_height = (card_height + desc_block_height).min(area.height);
    let block_y = area.y + (area.height.saturating_sub(total_height)) / 2;
    let card_x = area.x + (area.width.saturating_sub(card_width)) / 2;
    let card_area = Rect::new(card_x, block_y, card_width, card_height.min(area.height));

    // Draw the card with title
    let card = Card::new(Span::styled(" Menu ", styles::title())).focused(true);
    frame.render_widget(card, card_area);

    // Inner area for content
    let inner = Rect::new(
        card_area.x + 1,
        card_area.y + 1,
        card_area.width.saturating_sub(2),
        card_area.height.saturating_sub(2),
    );

    // Render rows
    for (row_idx, row) in rows.iter().enumerate() {
        let y = inner.y + row_idx as u16;
        if y >= inner.y + inner.height {
            break;
        }

        match row {
            MenuRow::Blank => {}
            MenuRow::Separator => {
                render_separator_line(frame, inner, y);
            }
            MenuRow::Item(item_idx, item) => {
                render_menu_item(frame, inner, y, *item_idx, item, app);
            }
        }
    }

    // Render description block below the card.
    if let Some((title, body)) = desc {
        let desc_x = card_x;
        let mut y = card_area.y + card_area.height + 1; // blank row after card

        // Title line: just the label, accented.
        if y < area.y + area.height {
            let title_line = Line::from(vec![
                Span::raw("  "),
                Span::styled(title, styles::selected()),
            ]);
            let title_area = Rect::new(desc_x, y, desc_width, 1);
            frame.render_widget(Paragraph::new(title_line), title_area);
            y += 1;
        }

        // Body lines — render actual lines, but advance y by the reserved
        // height so the hint stays pinned regardless of body length.
        let body_start_y = y;
        for (i, line_text) in body.iter().enumerate() {
            let line_y = body_start_y + i as u16;
            if line_y >= area.y + area.height {
                break;
            }
            let body_line = Line::from(Span::styled(
                format!("  {line_text}"),
                Style::default().fg(colors::TEXT_SECONDARY),
            ));
            let body_area = Rect::new(desc_x, line_y, desc_width, 1);
            frame.render_widget(Paragraph::new(body_line), body_area);
        }
        y = body_start_y + DESC_BODY_RESERVED;

        // Blank, then hint
        y += 1;
        if y < area.y + area.height {
            let hint_text = if app.is_sharing() {
                "↑↓ navigate · Enter to stop · q to quit"
            } else {
                "↑↓ navigate · Enter to select · q to quit"
            };
            let hint = Paragraph::new(Line::from(Span::styled(hint_text, styles::hint())))
                .alignment(Alignment::Center);
            let hint_area = Rect::new(area.x, y, area.width, 1);
            frame.render_widget(hint, hint_area);
        }
    }
}

/// Per-item description shown below the menu. Returns (title, body_lines).
/// Body lines should be pre-wrapped to fit ~40 columns.
fn menu_item_description(item: &MenuItem, app: &App) -> (&'static str, Vec<&'static str>) {
    match item {
        MenuItem::StartSharing => (
            "Start VPN Sharing",
            vec![
                "Route your VPN traffic to LAN clients.",
                "Connect to your VPN first, then select",
                "the VPN and LAN interfaces.",
            ],
        ),
        MenuItem::StopSharing => (
            "Stop VPN Sharing",
            vec![
                "Tear down NAT, DHCP, and port mapping.",
                "Safe to run anytime — cleans up fully.",
            ],
        ),
        MenuItem::ToggleDhcp => {
            if !app.dnsmasq_installed {
                (
                    "DHCP Server (unavailable)",
                    vec![
                        "Hands out IPs automatically. Install:",
                        "  brew install dnsmasq",
                        "Without it, clients need static IPs.",
                    ],
                )
            } else {
                (
                    "DHCP Server",
                    vec![
                        "Hand out IPs to LAN clients via",
                        "dnsmasq. Disable for static IPs.",
                    ],
                )
            }
        }
        MenuItem::ToggleNatPmp => (
            "NAT-PMP Server",
            vec![
                "Let LAN apps auto-open ports through",
                "the gateway (games, file shares, etc).",
            ],
        ),
        MenuItem::SetDns => (
            "DNS Server",
            vec![
                "VPN-path resolver behind this Mac.",
                "LAN clients always query tunshare :53.",
            ],
        ),
        MenuItem::SetMtu => (
            "Tunnel MTU",
            vec![
                "Sets the MSS clamp for shared traffic.",
                "Auto measures the real path MTU; pin a",
                "value if you know your tunnel's MTU.",
            ],
        ),
        MenuItem::ViewLists => (
            "Lists",
            vec![
                "Block ads at DNS. Allowlist sends those",
                "domains out the WAN, around the VPN.",
                "Both off by default. Live while sharing.",
            ],
        ),
        MenuItem::RunDoctor => (
            "Run Doctor",
            vec![
                "Diagnose firewall, IP forwarding,",
                "interfaces, and dependencies.",
            ],
        ),
        MenuItem::Quit => (
            "Quit",
            vec![
                "Exit tunshare. Active sharing will be",
                "stopped and cleaned up automatically.",
            ],
        ),
    }
}

enum MenuRow<'a> {
    Blank,
    Separator,
    Item(usize, &'a MenuItem),
}

/// Width of a status badge when rendered. Mirrors the formatting in
/// `render_menu_item` so card sizing accounts for the actual cell count.
fn badge_width(badge: &StatusBadge) -> u16 {
    match badge {
        StatusBadge::On => (symbols::STATUS_ACTIVE.chars().count() + " ON".chars().count()) as u16,
        StatusBadge::Off => {
            (symbols::STATUS_INACTIVE.chars().count() + " OFF".chars().count()) as u16
        }
        StatusBadge::Value(v) | StatusBadge::Disabled(v) => v.chars().count() as u16,
    }
}

/// Render a dotted separator line across the inner width.
fn render_separator_line(frame: &mut Frame, inner: Rect, y: u16) {
    let padding = 3u16;
    let sep_x = inner.x + padding;
    let sep_width = inner.width.saturating_sub(padding * 2);
    let sep_str: String = symbols::SEPARATOR_CHAR.repeat(sep_width as usize);
    let line = Line::from(Span::styled(sep_str, styles::separator()));
    let sep_area = Rect::new(sep_x, y, sep_width, 1);
    frame.render_widget(Paragraph::new(line), sep_area);
}

/// Render a single menu item with left-aligned label and right-aligned status.
fn render_menu_item(
    frame: &mut Frame,
    inner: Rect,
    y: u16,
    item_idx: usize,
    item: &MenuItem,
    app: &App,
) {
    let is_selected = item_idx == app.selected_menu_item;

    let prefix = if is_selected {
        format!("  {}  ", symbols::SELECTED)
    } else {
        "     ".to_string()
    };

    let (label, status) = menu_item_label_status(item, app);

    let label_style = if is_selected {
        styles::selected()
    } else {
        styles::unselected()
    };

    let mut spans = vec![
        Span::styled(prefix, label_style),
        Span::styled(label, label_style),
    ];

    // Right-align status badge if present
    if let Some(badge) = status {
        let prefix_width = 5u16; // "     " or "  ▶  "
        let label_char_count = menu_item_label_str(item).len() as u16;
        let (badge_text, badge_style) = match badge {
            StatusBadge::On => (
                format!("{} ON", symbols::STATUS_ACTIVE),
                styles::status_on(),
            ),
            StatusBadge::Off => (
                format!("{} OFF", symbols::STATUS_INACTIVE),
                styles::status_off(),
            ),
            StatusBadge::Value(v) => (v, styles::hint()),
            StatusBadge::Disabled(v) => (v, styles::status_off()),
        };
        let badge_width = badge_text.chars().count() as u16;
        let gap = inner
            .width
            .saturating_sub(prefix_width + label_char_count + badge_width + 1);
        spans.push(Span::raw(" ".repeat(gap as usize)));
        if is_selected {
            spans.push(Span::styled(badge_text, label_style));
        } else {
            spans.push(Span::styled(badge_text, badge_style));
        }
    }

    let line = Line::from(spans);
    let item_area = Rect::new(inner.x, y, inner.width, 1);
    frame.render_widget(Paragraph::new(line), item_area);
}

/// Get the static label string for a menu item (for width calculation).
fn menu_item_label_str(item: &MenuItem) -> &'static str {
    match item {
        MenuItem::StartSharing => "Start VPN Sharing",
        MenuItem::StopSharing => "Stop VPN Sharing",
        MenuItem::ToggleDhcp => "DHCP Server",
        MenuItem::ToggleNatPmp => "NAT-PMP Server",
        MenuItem::SetDns => "DNS Server",
        MenuItem::SetMtu => "Tunnel MTU",
        MenuItem::ViewLists => "Lists",
        MenuItem::RunDoctor => "Run Doctor",
        MenuItem::Quit => "Quit",
    }
}

/// Get label and optional status badge for a menu item.
fn menu_item_label_status(item: &MenuItem, app: &App) -> (String, Option<StatusBadge>) {
    match item {
        MenuItem::StartSharing => ("Start VPN Sharing".to_string(), None),
        MenuItem::StopSharing => ("Stop VPN Sharing".to_string(), None),
        MenuItem::ToggleDhcp => {
            if !app.dnsmasq_installed {
                (
                    "DHCP Server".to_string(),
                    Some(StatusBadge::Disabled(
                        "Select to install dnsmasq".to_string(),
                    )),
                )
            } else if app.dhcp_enabled {
                ("DHCP Server".to_string(), Some(StatusBadge::On))
            } else {
                ("DHCP Server".to_string(), Some(StatusBadge::Off))
            }
        }
        MenuItem::ToggleNatPmp => {
            if app.natpmp_enabled {
                ("NAT-PMP Server".to_string(), Some(StatusBadge::On))
            } else {
                ("NAT-PMP Server".to_string(), Some(StatusBadge::Off))
            }
        }
        MenuItem::SetDns => {
            let value = match app.dns.custom.as_deref() {
                Some(dns) => dns.to_string(),
                None => app
                    .dns
                    .effective()
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "auto".to_string()),
            };
            ("DNS Server".to_string(), Some(StatusBadge::Value(value)))
        }
        MenuItem::SetMtu => (
            "Tunnel MTU".to_string(),
            Some(StatusBadge::Value(app.mtu.active_label())),
        ),
        MenuItem::ViewLists => {
            let badge = match (app.lists.block.enabled, app.lists.allow.enabled) {
                (true, true) => "block+allow",
                (true, false) => "block",
                (false, true) => "allow",
                (false, false) => "off",
            };
            (
                "Lists".to_string(),
                Some(StatusBadge::Value(badge.to_string())),
            )
        }
        MenuItem::RunDoctor => ("Run Doctor".to_string(), None),
        MenuItem::Quit => ("Quit".to_string(), None),
    }
}

/// Render the DNS editing overlay (dispatches by mode).
pub fn render_dns_edit(frame: &mut Frame, area: Rect, app: &App) {
    match app.dns.edit_mode {
        DnsEditMode::SelectingPreset => render_dns_preset_list(frame, area, app),
        DnsEditMode::CustomInput => render_dns_custom_input(frame, area, app),
    }
}

/// Render the DNS preset selection list.
fn render_dns_preset_list(frame: &mut Frame, area: Rect, app: &App) {
    // Build a flat list of rows. Selectable rows carry their picker index;
    // a divider row (between presets and history) carries None and isn't
    // reachable by the cursor.
    let name_col_width = 18u16;
    let has_history = !app.dns.history.is_empty();

    let mut rows: Vec<(Option<usize>, Line)> = Vec::new();

    // Build a row builder closure for selectable rows.
    let build_row = |is_selected: bool, content: Vec<Span<'static>>| -> Line<'static> {
        let prefix_text = if is_selected {
            format!("  {}  ", symbols::SELECTED)
        } else {
            "     ".to_string()
        };
        let style = if is_selected {
            styles::selected()
        } else {
            styles::unselected()
        };
        let mut spans = vec![Span::styled(prefix_text, style)];
        spans.extend(content);
        Line::from(spans)
    };

    let sel = app.dns.preset_selected;

    // Auto-detect
    {
        let is_selected = sel == 0;
        let style = if is_selected {
            styles::selected()
        } else {
            styles::unselected()
        };
        rows.push((
            Some(0),
            build_row(is_selected, vec![Span::styled("Auto-detect", style)]),
        ));
    }

    // Presets
    for (i, preset) in DNS_PRESETS.iter().enumerate() {
        let idx = 1 + i;
        let is_selected = sel == idx;
        let style = if is_selected {
            styles::selected()
        } else {
            styles::unselected()
        };
        let ip_style = if is_selected {
            style
        } else {
            Style::default().fg(colors::TEXT_SECONDARY)
        };
        let name = format!("{:<width$}", preset.name, width = name_col_width as usize);
        rows.push((
            Some(idx),
            build_row(
                is_selected,
                vec![
                    Span::styled(name, style),
                    Span::styled(preset.ip.to_string(), ip_style),
                ],
            ),
        ));
    }

    // History block (only if non-empty)
    if has_history {
        rows.push((
            None,
            Line::from(Span::styled(
                "     ── Recent ──",
                Style::default().fg(colors::TEXT_SECONDARY),
            )),
        ));
        let history_start = 1 + DNS_PRESETS.len();
        for (i, entry) in app.dns.history.iter().enumerate() {
            let idx = history_start + i;
            let is_selected = sel == idx;
            let style = if is_selected {
                styles::selected()
            } else {
                styles::unselected()
            };
            let hint_style = if is_selected {
                style
            } else {
                Style::default().fg(colors::TEXT_SECONDARY)
            };
            rows.push((
                Some(idx),
                build_row(
                    is_selected,
                    vec![
                        Span::styled(entry.clone(), style),
                        Span::styled("  [x: remove]", hint_style),
                    ],
                ),
            ));
        }
    }

    // Custom...
    {
        let idx = app.dns_custom_input_idx();
        let is_selected = sel == idx;
        let style = if is_selected {
            styles::selected()
        } else {
            styles::unselected()
        };
        rows.push((
            Some(idx),
            build_row(is_selected, vec![Span::styled("Custom...", style)]),
        ));
    }

    // Card sizing: rows + current line + top/bottom padding
    let row_count = rows.len() as u16;
    let card_width = 44u16.min(area.width.saturating_sub(4));
    let card_height = (row_count + 4).min(area.height.saturating_sub(2));
    let card_x = area.x + (area.width.saturating_sub(card_width)) / 2;
    let card_y = area.y + (area.height.saturating_sub(card_height)) / 2;
    let card_area = Rect::new(card_x, card_y, card_width, card_height);

    frame.render_widget(Clear, area);
    let card = Card::new(Span::styled(" Set DNS Server ", styles::card_title())).focused(true);
    frame.render_widget(card, card_area);

    let inner = Rect::new(
        card_area.x + 2,
        card_area.y + 1,
        card_area.width.saturating_sub(4),
        card_area.height.saturating_sub(2),
    );

    // Current value line
    let current_text = match app.dns.custom.as_deref() {
        Some(dns) => format!("Current: {} (custom)", dns),
        None => match app.dns.effective().first() {
            Some(dns) => format!("Current: {} ({})", dns, app.dns.source()),
            None => "Current: none".to_string(),
        },
    };
    let current_line = Line::from(Span::styled(
        current_text,
        Style::default().fg(colors::TEXT_SECONDARY),
    ));
    let current_area = Rect::new(inner.x, inner.y, inner.width, 1);
    frame.render_widget(Paragraph::new(current_line), current_area);

    // Render each row
    let items_y = inner.y + 2;
    for (offset, (_idx, line)) in rows.into_iter().enumerate() {
        let y = items_y + offset as u16;
        if y >= inner.y + inner.height {
            break;
        }
        let item_area = Rect::new(inner.x, y, inner.width, 1);
        frame.render_widget(Paragraph::new(line), item_area);
    }
}

/// Render the custom DNS text input.
fn render_dns_custom_input(frame: &mut Frame, area: Rect, app: &App) {
    let card_width = 44u16.min(area.width.saturating_sub(4));
    let card_height = 5u16;
    let card_x = area.x + (area.width.saturating_sub(card_width)) / 2;
    let card_y = area.y + (area.height.saturating_sub(card_height)) / 2;
    let card_area = Rect::new(card_x, card_y, card_width, card_height);

    frame.render_widget(Clear, area);
    let card = Card::new(Span::styled(" Custom DNS ", styles::card_title())).focused(true);
    frame.render_widget(card, card_area);

    let inner = Rect::new(
        card_area.x + 2,
        card_area.y + 1,
        card_area.width.saturating_sub(4),
        card_area.height.saturating_sub(2),
    );

    // Hint line
    let hint = Line::from(Span::styled(
        "Enter IP or leave empty to auto-detect",
        Style::default().fg(colors::TEXT_SECONDARY),
    ));
    let hint_area = Rect::new(inner.x, inner.y, inner.width, 1);
    frame.render_widget(Paragraph::new(hint), hint_area);

    // Input line with cursor
    let input_display = format!("{}█", app.dns.input_buffer);
    let input_line = Line::from(vec![
        Span::styled("DNS: ", Style::default().fg(colors::TEXT_SECONDARY)),
        Span::styled(
            input_display,
            Style::default()
                .fg(colors::TEXT_PRIMARY)
                .add_modifier(Modifier::BOLD),
        ),
    ]);
    let input_area = Rect::new(inner.x, inner.y + 2, inner.width, 1);
    frame.render_widget(Paragraph::new(input_line), input_area);
}

/// Render the MTU editing overlay (dispatches by mode).
pub fn render_mtu_edit(frame: &mut Frame, area: Rect, app: &App) {
    match app.mtu.edit_mode {
        MtuEditMode::SelectingPreset => render_mtu_preset_list(frame, area, app),
        MtuEditMode::CustomInput => render_mtu_custom_input(frame, area, app),
    }
}

fn render_mtu_preset_list(frame: &mut Frame, area: Rect, app: &App) {
    let card_width = 48u16.min(area.width.saturating_sub(4));
    let row_count = MTU_PRESETS.len() as u16;
    let card_height = (row_count + 4).min(area.height.saturating_sub(2));
    let card_x = area.x + (area.width.saturating_sub(card_width)) / 2;
    let card_y = area.y + (area.height.saturating_sub(card_height)) / 2;
    let card_area = Rect::new(card_x, card_y, card_width, card_height);

    frame.render_widget(Clear, area);
    let card = Card::new(Span::styled(" Set Tunnel MTU ", styles::card_title())).focused(true);
    frame.render_widget(card, card_area);

    let inner = Rect::new(
        card_area.x + 2,
        card_area.y + 1,
        card_area.width.saturating_sub(4),
        card_area.height.saturating_sub(2),
    );

    // Current value summary.
    let current_text = format!("Current: {}", app.mtu.active_label());
    let current_line = Line::from(Span::styled(
        current_text,
        Style::default().fg(colors::TEXT_SECONDARY),
    ));
    let current_area = Rect::new(inner.x, inner.y, inner.width, 1);
    frame.render_widget(Paragraph::new(current_line), current_area);

    let items_y = inner.y + 2;
    let sel = app.mtu.preset_selected;
    for (i, preset) in MTU_PRESETS.iter().enumerate() {
        let y = items_y + i as u16;
        if y >= inner.y + inner.height {
            break;
        }
        let is_selected = sel == i;
        let style = if is_selected {
            styles::selected()
        } else {
            styles::unselected()
        };
        let prefix = if is_selected {
            format!("  {}  ", symbols::SELECTED)
        } else {
            "     ".to_string()
        };
        let (label, hint) = match preset {
            MtuPreset::Auto => ("Auto".to_string(), "measure path MTU".to_string()),
            MtuPreset::Fixed(n, kind) => (format!("{n}"), (*kind).to_string()),
            MtuPreset::Custom => ("Custom...".to_string(), String::new()),
        };
        let hint_style = if is_selected {
            style
        } else {
            Style::default().fg(colors::TEXT_SECONDARY)
        };
        let mut spans = vec![
            Span::styled(prefix, style),
            Span::styled(format!("{:<22}", label), style),
        ];
        if !hint.is_empty() {
            spans.push(Span::styled(hint, hint_style));
        }
        let item_area = Rect::new(inner.x, y, inner.width, 1);
        frame.render_widget(Paragraph::new(Line::from(spans)), item_area);
    }
}

fn render_mtu_custom_input(frame: &mut Frame, area: Rect, app: &App) {
    let card_width = 44u16.min(area.width.saturating_sub(4));
    let card_height = 5u16;
    let card_x = area.x + (area.width.saturating_sub(card_width)) / 2;
    let card_y = area.y + (area.height.saturating_sub(card_height)) / 2;
    let card_area = Rect::new(card_x, card_y, card_width, card_height);

    frame.render_widget(Clear, area);
    let card = Card::new(Span::styled(" Custom Tunnel MTU ", styles::card_title())).focused(true);
    frame.render_widget(card, card_area);

    let inner = Rect::new(
        card_area.x + 2,
        card_area.y + 1,
        card_area.width.saturating_sub(4),
        card_area.height.saturating_sub(2),
    );

    let hint = Line::from(Span::styled(
        "Bytes (576 – 9000)",
        Style::default().fg(colors::TEXT_SECONDARY),
    ));
    let hint_area = Rect::new(inner.x, inner.y, inner.width, 1);
    frame.render_widget(Paragraph::new(hint), hint_area);

    let input_display = format!("{}█", app.mtu.input_buffer);
    let input_line = Line::from(vec![
        Span::styled("MTU: ", Style::default().fg(colors::TEXT_SECONDARY)),
        Span::styled(
            input_display,
            Style::default()
                .fg(colors::TEXT_PRIMARY)
                .add_modifier(Modifier::BOLD),
        ),
    ]);
    let input_area = Rect::new(inner.x, inner.y + 2, inner.width, 1);
    frame.render_widget(Paragraph::new(input_line), input_area);
}

/// Render connection info when sharing is active — single merged card with diagram + config.
pub fn render_connection_info(frame: &mut Frame, area: Rect, app: &App) {
    if !app.is_sharing() {
        return;
    }

    let (Some(vpn_idx), Some(lan_idx)) = (app.selected_vpn, app.selected_lan) else {
        return;
    };

    let (Some(vpn), Some(lan)) = (
        app.vpn_interfaces.get(vpn_idx),
        app.lan_interfaces.get(lan_idx),
    ) else {
        return;
    };

    let vpn_ip = vpn
        .ipv4_address
        .map(|a| a.to_string())
        .unwrap_or_else(|| "?.?.?.?".into());
    let lan_ip = lan
        .ipv4_address
        .map(|a| a.to_string())
        .unwrap_or_else(|| "?.?.?.?".into());

    // Draw a single card over the full area
    let card = Card::new(Span::styled(" Connection ", styles::card_title())).focused(true);
    frame.render_widget(card, area);

    let inner = Rect::new(
        area.x + 2,
        area.y + 1,
        area.width.saturating_sub(4),
        area.height.saturating_sub(2),
    );

    // Layout:
    //  row 0: blank
    //  row 1: VPN/LAN labels
    //  row 2-4: interface boxes (3 rows)
    //  row 5: blank
    //  row 6: separator
    //  row 7: blank
    //  row 8-11: config rows (4 rows)

    let diagram_start_y = inner.y + 1;

    // Render diagram inline (labels + boxes + arrow)
    render_diagram_inner(
        frame,
        inner,
        diagram_start_y,
        &vpn.name,
        &vpn_ip,
        &lan.name,
        &lan_ip,
    );

    // Separator after diagram (labels row + 3 box rows + 1 blank = 5 rows from diagram_start_y)
    let sep_y = diagram_start_y + 5;
    if sep_y < inner.y + inner.height {
        render_separator_line(frame, inner, sep_y);
    }

    // Config rows start after separator + blank
    let config_start_y = sep_y + 2;
    render_config_rows(frame, inner, config_start_y, &lan_ip, app);

    // Traffic block: separator + blank + 3 rows (down, up, totals).
    let traffic_sep_y = config_start_y + 5;
    let traffic_block_end = traffic_sep_y + 5;
    if let Some(session) = app.session.as_ref() {
        if traffic_block_end <= inner.y + inner.height {
            render_separator_line(frame, inner, traffic_sep_y);
            render_traffic_block(frame, inner, traffic_sep_y + 2, &session.traffic);
        }
    }
}

/// Render the down/up/total traffic block at the given y.
fn render_traffic_block(frame: &mut Frame, inner: Rect, start_y: u16, stats: &TrafficStats) {
    let padding = 3u16;
    let usable_width = inner.width.saturating_sub(padding * 2);

    // Compute the sparkline budget from the *actual* rendered widths so a
    // tweak to the label or rate format can't silently break alignment.
    const DOWN_LABEL: &str = "↓ Down  ";
    const UP_LABEL: &str = "↑ Up    ";
    const RATE_WIDTH: u16 = 9; // matches the `{:>9}` formatter below
    const GUTTER: u16 = 2; // spaces between sparkline and rate
    let label_width = DOWN_LABEL.chars().count().max(UP_LABEL.chars().count()) as u16;
    // Fill all remaining horizontal space — keep a small floor so the
    // sparkline stays legible in pathologically narrow terminals.
    let spark_width = usable_width
        .saturating_sub(label_width + GUTTER + RATE_WIDTH)
        .max(8);

    let down_rate = format_rate(stats.rate_down);
    let up_rate = format_rate(stats.rate_up);
    let down_spark = stats.sparkline_down(spark_width as usize);
    let up_spark = stats.sparkline_up(spark_width as usize);

    let down_color = colors::SUCCESS;
    let up_color = colors::LAN;

    // Row 1: ↓ Down   <spark>   <rate>
    let line_down = Line::from(vec![
        Span::styled(
            DOWN_LABEL,
            Style::default().fg(down_color).add_modifier(Modifier::BOLD),
        ),
        Span::styled(down_spark, Style::default().fg(down_color)),
        Span::raw("  "),
        Span::styled(
            format!("{:>width$}", down_rate, width = RATE_WIDTH as usize),
            Style::default().fg(colors::TEXT_PRIMARY),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(line_down),
        Rect::new(inner.x + padding, start_y, usable_width, 1),
    );

    // Row 2: ↑ Up     <spark>   <rate>
    let line_up = Line::from(vec![
        Span::styled(
            UP_LABEL,
            Style::default().fg(up_color).add_modifier(Modifier::BOLD),
        ),
        Span::styled(up_spark, Style::default().fg(up_color)),
        Span::raw("  "),
        Span::styled(
            format!("{:>width$}", up_rate, width = RATE_WIDTH as usize),
            Style::default().fg(colors::TEXT_PRIMARY),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(line_up),
        Rect::new(inner.x + padding, start_y + 1, usable_width, 1),
    );

    // Row 3 (blank), row 4: Total   ↓ <bytes>   ↑ <bytes>
    let total_label = Span::styled("Total", Style::default().fg(colors::TEXT_SECONDARY));
    let total_value = Line::from(vec![
        Span::styled("↓ ", Style::default().fg(down_color)),
        Span::styled(
            format_bytes(stats.total_down),
            Style::default().fg(colors::TEXT_PRIMARY),
        ),
        Span::raw("   "),
        Span::styled("↑ ", Style::default().fg(up_color)),
        Span::styled(
            format_bytes(stats.total_up),
            Style::default().fg(colors::TEXT_PRIMARY),
        ),
    ]);
    let total_value_str: String = total_value
        .spans
        .iter()
        .map(|s| s.content.as_ref())
        .collect();
    let total_value_width = total_value_str.chars().count() as u16;
    let label_w = "Total".chars().count() as u16;
    let gap = usable_width.saturating_sub(label_w + total_value_width);
    let mut spans = vec![total_label, Span::raw(" ".repeat(gap as usize))];
    spans.extend(total_value.spans);
    frame.render_widget(
        Paragraph::new(Line::from(spans)),
        Rect::new(inner.x + padding, start_y + 3, usable_width, 1),
    );
}

/// Render the diagram (labels, boxes, arrow) into the given inner area at the specified y offset.
fn render_diagram_inner(
    frame: &mut Frame,
    inner: Rect,
    start_y: u16,
    vpn_name: &str,
    vpn_ip: &str,
    lan_name: &str,
    lan_ip: &str,
) {
    let box_width = 16u16;
    let arrow_width = 10u16;
    let total_width = box_width * 2 + arrow_width;

    let start_x = inner.x + (inner.width.saturating_sub(total_width)) / 2;

    // Labels row
    let label_y = start_y;
    let vpn_label = Paragraph::new(Line::from(Span::styled(
        "VPN",
        styles::vpn_interface().add_modifier(Modifier::BOLD),
    )))
    .alignment(Alignment::Center);
    let vpn_label_area = Rect::new(start_x, label_y, box_width, 1);
    frame.render_widget(vpn_label, vpn_label_area);

    let lan_box_x = start_x + box_width + arrow_width;
    let lan_label = Paragraph::new(Line::from(Span::styled(
        "LAN",
        styles::lan_interface().add_modifier(Modifier::BOLD),
    )))
    .alignment(Alignment::Center);
    let lan_label_area = Rect::new(lan_box_x, label_y, box_width, 1);
    frame.render_widget(lan_label, lan_label_area);

    // Boxes (3 rows starting at label_y + 1)
    let box_y = label_y + 1;
    let vpn_box_area = Rect::new(start_x, box_y, box_width, 3);
    render_interface_box(frame, vpn_box_area, vpn_name, vpn_ip, true);

    let lan_box_area = Rect::new(lan_box_x, box_y, box_width, 3);
    render_interface_box(frame, lan_box_area, lan_name, lan_ip, false);

    // Arrow (centered vertically in box, i.e. box_y + 1)
    let arrow_x = start_x + box_width + 2;
    let arrow = Span::styled(symbols::ARROW_RIGHT, Style::default().fg(colors::ACCENT));
    let arrow_area = Rect::new(arrow_x, box_y + 1, arrow_width.saturating_sub(4), 1);
    frame.render_widget(Paragraph::new(Line::from(arrow)), arrow_area);
}

/// Render config items as a vertical 2-column table (label left, value right).
fn render_config_rows(frame: &mut Frame, inner: Rect, start_y: u16, gateway: &str, app: &App) {
    let dns_servers = app.dns.effective();
    let dns_source = app.dns.source();
    let dhcp_active = app.dhcp_active();
    let dhcp_range = app.dhcp_range();
    let natpmp_active = app.natpmp_active();

    let dns_str = if dns_servers.is_empty() {
        "none".to_string()
    } else {
        format!(
            "{} ({})",
            dns_servers.first().cloned().unwrap_or_default(),
            dns_source
        )
    };

    let dhcp_status = if dhcp_active {
        if let Some((start, end)) = dhcp_range {
            format!(
                "DHCP {}-{}",
                start.split('.').next_back().unwrap_or("?"),
                end.split('.').next_back().unwrap_or("?")
            )
        } else {
            "DHCP Active".to_string()
        }
    } else {
        "Manual".to_string()
    };

    let natpmp_status = if natpmp_active { "Active" } else { "Off" };

    // Effective tunnel MTU + the MSS clamp it drives. This is the *effective*
    // MTU (probed path MTU, a manual Fixed value, or the conservative cap) —
    // not the tunnel's raw interface MTU — so it reflects what the clamp
    // actually uses and makes a VPN-switch reload visible.
    let tunnel_str = match app.session.as_ref() {
        Some(s) if s.upstream.effective_mtu > 0 => {
            format!("{} (MSS {})", s.upstream.effective_mtu, s.upstream.mss_v4())
        }
        _ => "—".to_string(),
    };

    let config_items: &[(&str, String, bool)] = &[
        ("Gateway", gateway.to_string(), false),
        ("Tunnel", tunnel_str, false),
        ("DNS", dns_str, false),
        ("WAN", dhcp_status, dhcp_active),
        ("NAT-PMP", natpmp_status.to_string(), natpmp_active),
    ];

    let padding = 3u16;

    for (i, (label, value, is_active)) in config_items.iter().enumerate() {
        let y = start_y + i as u16;
        if y >= inner.y + inner.height {
            break;
        }

        let label_span = Span::styled(
            label.to_string(),
            Style::default().fg(colors::TEXT_SECONDARY),
        );

        let value_style = if *is_active {
            Style::default().fg(colors::SUCCESS)
        } else {
            Style::default().fg(colors::TEXT_PRIMARY)
        };
        let value_span = Span::styled(value.clone(), value_style);

        // Left-aligned label, right-aligned value
        let label_width = label.len() as u16;
        let value_width = value.len() as u16;
        let usable_width = inner.width.saturating_sub(padding * 2);
        let gap = usable_width.saturating_sub(label_width + value_width);

        let line = Line::from(vec![
            label_span,
            Span::raw(" ".repeat(gap as usize)),
            value_span,
        ]);

        let row_area = Rect::new(inner.x + padding, y, usable_width, 1);
        frame.render_widget(Paragraph::new(line), row_area);
    }
}

/// Render an interface box.
fn render_interface_box(frame: &mut Frame, area: Rect, name: &str, ip: &str, is_vpn: bool) {
    let style = if is_vpn {
        styles::vpn_interface()
    } else {
        styles::lan_interface()
    };

    // Draw box border using card
    let card = Card::empty().border_style(style);
    frame.render_widget(card, area);

    // Draw name
    let name_display = if name.len() > area.width.saturating_sub(2) as usize {
        &name[..area.width.saturating_sub(2) as usize]
    } else {
        name
    };
    let name_para =
        Paragraph::new(Line::from(Span::styled(name_display, style))).alignment(Alignment::Center);
    let name_area = Rect::new(area.x + 1, area.y + 1, area.width.saturating_sub(2), 1);
    frame.render_widget(name_para, name_area);

    // Draw IP below
    let ip_display = ip;

    if area.height > 2 {
        let ip_para = Paragraph::new(Line::from(Span::styled(
            ip_display,
            Style::default().fg(colors::TEXT_SECONDARY),
        )))
        .alignment(Alignment::Center);
        let ip_area = Rect::new(area.x + 1, area.y + 2, area.width.saturating_sub(2), 1);
        frame.render_widget(ip_para, ip_area);
    }
}
