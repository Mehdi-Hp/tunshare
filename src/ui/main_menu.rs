//! Main menu and header rendering.

use ratatui::{
    layout::{Alignment, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Clear, Paragraph},
    Frame,
};

use crate::app::{App, AppState, DnsEditMode, MenuItem, DNS_PRESETS};
use crate::health::HealthStatus;
use crate::ui::theme::{borders, colors, styles, symbols};
use crate::ui::widgets::Card;

/// Render the single-line header with app title and status badge.
pub fn render_header(frame: &mut Frame, area: Rect, app: &App) {
    let (status_text, status_style, status_icon) = if app.is_sharing() {
        match app.health_status() {
            HealthStatus::Healthy => ("Active", styles::status_active(), symbols::STATUS_ACTIVE),
            HealthStatus::Degraded(_) => ("Degraded", styles::status_degraded(), symbols::WARNING),
            HealthStatus::Down(_) => ("VPN Down", styles::status_down(), symbols::ERROR),
        }
    } else {
        let text = match app.state {
            AppState::SelectingVpn | AppState::SelectingLan | AppState::EditingDns => "Configuring",
            _ => "Inactive",
        };
        (text, styles::status_inactive(), symbols::STATUS_INACTIVE)
    };

    // Build the header line
    let title = Span::styled(format!("{} VPN Share", symbols::APP_ICON), styles::title());

    let status = Span::styled(format!("{} {}", status_icon, status_text), status_style);

    // Calculate spacing
    let title_width = title.content.chars().count();
    let status_width = status.content.chars().count();
    let spacing = area.width as usize - title_width - status_width;

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
            MenuItem::ToggleDhcp | MenuItem::ToggleNatPmp | MenuItem::SetDns => {
                group_settings.push((i, item))
            }
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

    // Calculate card dimensions
    let card_content_width = 42u16.max(area.width / 3);
    let card_content_height = rows.len() as u16;
    let card_width = (card_content_width + 2).min(area.width);
    let card_height = (card_content_height + 2).min(area.height.saturating_sub(2));

    // Center the card
    let card_x = area.x + (area.width.saturating_sub(card_width)) / 2;
    let card_y = area.y + (area.height.saturating_sub(card_height)) / 2;
    let card_area = Rect::new(card_x, card_y, card_width, card_height);

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

    // Draw hint below card
    let hint_y = card_area.y + card_area.height + 1;
    if hint_y < area.y + area.height {
        let hint_text = if app.is_sharing() {
            "Press Enter to stop"
        } else {
            "Press Enter to start"
        };
        let hint = Paragraph::new(Line::from(Span::styled(hint_text, styles::hint())))
            .alignment(Alignment::Center);
        let hint_area = Rect::new(area.x, hint_y, area.width, 1);
        frame.render_widget(hint, hint_area);
    }
}

enum MenuRow<'a> {
    Blank,
    Separator,
    Item(usize, &'a MenuItem),
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
    let is_disabled = is_menu_item_disabled(item, app);

    let prefix = if is_selected && !is_disabled {
        format!("  {}  ", symbols::SELECTED)
    } else {
        "     ".to_string()
    };

    let (label, status) = menu_item_label_status(item, app);

    let label_style = if is_disabled {
        Style::default().fg(colors::TEXT_SECONDARY)
    } else if is_selected {
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
        let badge_width = badge_text.len() as u16;
        let gap = inner
            .width
            .saturating_sub(prefix_width + label_char_count + badge_width + 1);
        spans.push(Span::raw(" ".repeat(gap as usize)));
        if is_selected && !is_disabled {
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
                    Some(StatusBadge::Disabled("not installed".to_string())),
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
            let value = if let Some(ref dns) = app.dns.custom {
                dns.clone()
            } else {
                let effective = app.dns.effective();
                if effective.is_empty() {
                    "auto".to_string()
                } else {
                    effective.first().unwrap().clone()
                }
            };
            ("DNS Server".to_string(), Some(StatusBadge::Value(value)))
        }
        MenuItem::Quit => ("Quit".to_string(), None),
    }
}

/// Check if a menu item should be disabled (grayed out).
fn is_menu_item_disabled(item: &MenuItem, app: &App) -> bool {
    matches!(item, MenuItem::ToggleDhcp if !app.dnsmasq_installed)
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
    // Items: Auto-detect, presets..., Custom...
    let item_count = 1 + DNS_PRESETS.len() + 1; // auto + presets + custom
    let card_width = 44u16.min(area.width.saturating_sub(4));
    let card_height = (item_count as u16 + 4).min(area.height.saturating_sub(2)); // items + current line + padding
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
    let current_text = if let Some(ref dns) = app.dns.custom {
        format!("Current: {} (custom)", dns)
    } else {
        let effective = app.dns.effective();
        if effective.is_empty() {
            "Current: none".to_string()
        } else {
            format!(
                "Current: {} ({})",
                effective.first().unwrap(),
                app.dns.source()
            )
        }
    };
    let current_line = Line::from(Span::styled(
        current_text,
        Style::default().fg(colors::TEXT_SECONDARY),
    ));
    let current_area = Rect::new(inner.x, inner.y, inner.width, 1);
    frame.render_widget(Paragraph::new(current_line), current_area);

    // Render each item
    let items_y = inner.y + 2; // gap after current line
    let name_col_width = 18u16;

    for i in 0..item_count {
        let y = items_y + i as u16;
        if y >= inner.y + inner.height {
            break;
        }

        let is_selected = i == app.dns.preset_selected;
        let prefix = if is_selected {
            format!("  {}  ", symbols::SELECTED)
        } else {
            "     ".to_string()
        };

        let style = if is_selected {
            styles::selected()
        } else {
            styles::unselected()
        };

        let line = if i == 0 {
            // Auto-detect
            Line::from(vec![
                Span::styled(prefix, style),
                Span::styled("Auto-detect", style),
            ])
        } else if i <= DNS_PRESETS.len() {
            let preset = &DNS_PRESETS[i - 1];
            let name = format!("{:<width$}", preset.name, width = name_col_width as usize);
            Line::from(vec![
                Span::styled(prefix, style),
                Span::styled(name, style),
                Span::styled(
                    preset.ip,
                    if is_selected {
                        style
                    } else {
                        Style::default().fg(colors::TEXT_SECONDARY)
                    },
                ),
            ])
        } else {
            // Custom...
            Line::from(vec![
                Span::styled(prefix, style),
                Span::styled("Custom...", style),
            ])
        };

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

    let config_items: &[(&str, String, bool)] = &[
        ("Gateway", gateway.to_string(), false),
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
