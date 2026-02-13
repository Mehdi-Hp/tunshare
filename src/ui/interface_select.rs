//! Interface selection wizard rendering.
//!
//! Step-based interface selection with tree-style details.

use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

use crate::app::App;
use crate::system::InterfaceInfo;
use crate::ui::theme::{colors, styles, symbols};
use crate::ui::widgets::Card;

/// Render the VPN interface selection (Step 1).
pub fn render_vpn_selection(frame: &mut Frame, area: Rect, app: &App) {
    // Step indicator
    let step_area = Rect::new(area.x + 2, area.y, area.width.saturating_sub(4), 2);
    render_step_indicator(frame, step_area, 1, 2, "Select VPN Interface");

    // Content area below step indicator
    let content_area = Rect::new(
        area.x,
        area.y + 3,
        area.width,
        area.height.saturating_sub(3),
    );

    if app.vpn_interfaces.is_empty() {
        render_no_interfaces(
            frame,
            content_area,
            "VPN Interfaces",
            "No VPN interfaces found",
        );
    } else {
        render_interface_list(
            frame,
            content_area,
            "VPN Interfaces",
            &app.vpn_interfaces,
            app.selected_vpn,
            true,
        );
    }
}

/// Render the LAN interface selection (Step 2).
pub fn render_lan_selection(frame: &mut Frame, area: Rect, app: &App) {
    // Step indicator
    let step_area = Rect::new(area.x + 2, area.y, area.width.saturating_sub(4), 2);
    render_step_indicator(frame, step_area, 2, 2, "Select LAN Interface");

    // Split content area for VPN summary and LAN selection
    let content_area = Rect::new(
        area.x,
        area.y + 3,
        area.width,
        area.height.saturating_sub(3),
    );

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // VPN summary
            Constraint::Min(6),    // LAN selection
        ])
        .split(content_area);

    // Render VPN summary
    if let Some(vpn_idx) = app.selected_vpn {
        if let Some(vpn) = app.vpn_interfaces.get(vpn_idx) {
            let effective_dns = app.effective_dns();
            let dns_source = app.dns_source();
            render_selected_vpn_summary(frame, chunks[0], vpn, &effective_dns, dns_source);
        }
    }

    // Render LAN interface list
    if app.lan_interfaces.is_empty() {
        render_no_interfaces(
            frame,
            chunks[1],
            "LAN Interfaces",
            "No LAN interfaces found",
        );
    } else {
        render_interface_list(
            frame,
            chunks[1],
            "LAN Interfaces",
            &app.lan_interfaces,
            app.selected_lan,
            true,
        );
    }
}

/// Render the step indicator line.
fn render_step_indicator(frame: &mut Frame, area: Rect, current: u8, total: u8, description: &str) {
    let step_text = format!("Step {} of {}: {}", current, total, description);
    let step_line = Line::from(vec![Span::styled(step_text, styles::step_indicator())]);

    let step_para = Paragraph::new(step_line);
    frame.render_widget(step_para, area);

    // Draw underline
    if area.height > 1 {
        let mut underline = String::new();
        for _ in 0..description.len() + 12 {
            underline.push_str(
                symbols::TREE_END
                    .chars()
                    .next()
                    .unwrap_or('─')
                    .to_string()
                    .as_str(),
            );
            underline.push('─');
        }
        let underline_area = Rect::new(area.x, area.y + 1, area.width, 1);
        let underline_para = Paragraph::new(Line::from(Span::styled(
            "─".repeat((description.len() + 12).min(area.width as usize)),
            styles::border_unfocused(),
        )));
        frame.render_widget(underline_para, underline_area);
    }
}

/// Render the selected VPN summary card.
fn render_selected_vpn_summary(
    frame: &mut Frame,
    area: Rect,
    vpn: &InterfaceInfo,
    dns_servers: &[String],
    dns_source: &str,
) {
    let card = Card::new(Span::styled(" Selected VPN ", styles::card_title()));
    frame.render_widget(card, area);

    let inner = Rect::new(
        area.x + 2,
        area.y + 1,
        area.width.saturating_sub(4),
        area.height.saturating_sub(2),
    );

    let ip = vpn
        .ipv4_address
        .map(|a| a.to_string())
        .unwrap_or_else(|| "?.?.?.?".into());
    let dns_display = if dns_servers.is_empty() {
        "none".to_string()
    } else {
        format!(
            "{} ({})",
            dns_servers.first().cloned().unwrap_or_default(),
            dns_source
        )
    };

    let summary_line = Line::from(vec![
        Span::styled(
            &vpn.name,
            styles::vpn_interface().add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(symbols::STATUS_ACTIVE, styles::status_active()),
        Span::raw("  "),
        Span::styled(ip, Style::default().fg(colors::TEXT_PRIMARY)),
        Span::raw("    "),
        Span::styled("DNS: ", Style::default().fg(colors::TEXT_SECONDARY)),
        Span::styled(dns_display, Style::default().fg(colors::TEXT_PRIMARY)),
    ]);

    let summary_para = Paragraph::new(summary_line);
    frame.render_widget(summary_para, inner);
}

/// Render interface list with tree-style details.
fn render_interface_list(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    interfaces: &[InterfaceInfo],
    selected: Option<usize>,
    is_focused: bool,
) {
    // Determine if this is VPN or LAN based on title
    let is_vpn = title.contains("VPN");

    let card = Card::new(Span::styled(format!(" {} ", title), styles::card_title()))
        .focused(is_focused)
        .item_count(interfaces.len());

    frame.render_widget(card, area);

    let inner = Rect::new(
        area.x + 2,
        area.y + 1,
        area.width.saturating_sub(4),
        area.height.saturating_sub(2),
    );

    // Render each interface with tree-style details
    let mut y_offset = 0u16;
    for (i, iface) in interfaces.iter().enumerate() {
        if y_offset >= inner.height {
            break;
        }

        let is_selected = selected == Some(i);

        // Main interface line
        let prefix = if is_selected && is_focused {
            format!("{} ", symbols::SELECTED)
        } else {
            "  ".to_string()
        };

        let name_style = if is_selected {
            if is_vpn {
                styles::vpn_interface().add_modifier(Modifier::BOLD)
            } else {
                styles::lan_interface().add_modifier(Modifier::BOLD)
            }
        } else {
            styles::unselected()
        };

        // Interface name with optional description
        let display_name = if let Some(ref desc) = iface.description {
            format!("{} ({})", iface.name, desc)
        } else {
            iface.name.clone()
        };

        let main_line = Line::from(vec![
            Span::styled(prefix, name_style),
            Span::styled(display_name, name_style),
        ]);

        let main_area = Rect::new(inner.x, inner.y + y_offset, inner.width, 1);
        frame.render_widget(Paragraph::new(main_line), main_area);
        y_offset += 1;

        // Tree-style details (only for selected or if there's space)
        if is_selected && y_offset + 2 <= inner.height {
            // IP line
            if let Some(ip) = iface.ipv4_address {
                let ip_line = Line::from(vec![
                    Span::styled(
                        format!("  {} ", symbols::TREE_BRANCH),
                        styles::tree_branch(),
                    ),
                    Span::styled("IP: ", Style::default().fg(colors::TEXT_SECONDARY)),
                    Span::styled(ip.to_string(), Style::default().fg(colors::TEXT_PRIMARY)),
                ]);
                let ip_area = Rect::new(inner.x, inner.y + y_offset, inner.width, 1);
                frame.render_widget(Paragraph::new(ip_line), ip_area);
                y_offset += 1;
            }

            // Status line
            let status_icon = symbols::STATUS_ACTIVE;
            let status_text = "Connected";
            let status_style = styles::status_active();

            let status_line = Line::from(vec![
                Span::styled(format!("  {} ", symbols::TREE_END), styles::tree_branch()),
                Span::styled("Status: ", Style::default().fg(colors::TEXT_SECONDARY)),
                Span::styled(format!("{} {}", status_icon, status_text), status_style),
            ]);
            let status_area = Rect::new(inner.x, inner.y + y_offset, inner.width, 1);
            frame.render_widget(Paragraph::new(status_line), status_area);
            y_offset += 1;

            // Add spacing after selected item
            y_offset += 1;
        }
    }
}

/// Render a message when no interfaces are found.
pub fn render_no_interfaces(frame: &mut Frame, area: Rect, title: &str, message: &str) {
    let card = Card::new(Span::styled(format!(" {} ", title), styles::card_title()));
    frame.render_widget(card, area);

    let inner = Rect::new(
        area.x + 2,
        area.y + 1,
        area.width.saturating_sub(4),
        area.height.saturating_sub(2),
    );

    let msg_line = Line::from(vec![
        Span::styled(symbols::WARNING, Style::default().fg(colors::WARNING)),
        Span::raw(" "),
        Span::styled(message, Style::default().fg(colors::ERROR)),
    ]);

    let msg_para = Paragraph::new(msg_line).alignment(Alignment::Center);

    // Center vertically
    let msg_y = inner.y + inner.height / 2;
    let msg_area = Rect::new(inner.x, msg_y, inner.width, 1);
    frame.render_widget(msg_para, msg_area);
}
