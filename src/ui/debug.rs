//! Debug panel for displaying system state.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
    Frame,
};

use crate::app::DebugInfo;
use crate::ui::theme::{colors, styles, symbols};
use crate::ui::widgets::Card;

/// Render the debug panel filling the content area.
pub fn render_debug_panel(frame: &mut Frame, area: Rect, debug_info: &DebugInfo) {
    // Split into sections
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8), // System Status (expanded to include sample states)
            Constraint::Min(8),    // PF rules (gets more room)
        ])
        .split(area);

    // Render status summary (includes sample connections)
    render_status_summary(frame, chunks[0], debug_info);

    // Render PF rules
    render_pf_rules(frame, chunks[1], debug_info);
}

fn render_status_summary(frame: &mut Frame, area: Rect, info: &DebugInfo) {
    let pf_status = if info.pf_enabled {
        Span::styled(
            format!("{} Enabled", symbols::STATUS_ACTIVE),
            Style::default().fg(colors::SUCCESS),
        )
    } else {
        Span::styled(
            format!("{} Disabled", symbols::STATUS_INACTIVE),
            Style::default().fg(colors::ERROR),
        )
    };

    let ip_fwd_status = if info.ip_forwarding_enabled {
        Span::styled(
            format!("{} Enabled", symbols::STATUS_ACTIVE),
            Style::default().fg(colors::SUCCESS),
        )
    } else {
        Span::styled(
            format!("{} Disabled", symbols::STATUS_INACTIVE),
            Style::default().fg(colors::WARNING),
        )
    };

    let ip_fwd_modified = if info.ip_forwarding_modified {
        Span::styled(" (modified)", Style::default().fg(colors::ACCENT))
    } else {
        Span::raw("")
    };

    let dhcp_status = if info.dhcp_running {
        if let Some((start, end)) = &info.dhcp_range {
            Span::styled(
                format!("{} Active ({}-{})", symbols::STATUS_ACTIVE, start, end),
                Style::default().fg(colors::SUCCESS),
            )
        } else {
            Span::styled(
                format!("{} Active", symbols::STATUS_ACTIVE),
                Style::default().fg(colors::SUCCESS),
            )
        }
    } else {
        Span::styled(
            format!("{} Disabled", symbols::STATUS_INACTIVE),
            Style::default().fg(colors::TEXT_SECONDARY),
        )
    };

    let natpmp_status = if info.natpmp_running {
        Span::styled(
            format!("{} Active", symbols::STATUS_ACTIVE),
            Style::default().fg(colors::SUCCESS),
        )
    } else {
        Span::styled(
            format!("{} Disabled", symbols::STATUS_INACTIVE),
            Style::default().fg(colors::TEXT_SECONDARY),
        )
    };

    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                "  PF Firewall:   ",
                Style::default().fg(colors::TEXT_SECONDARY),
            ),
            pf_status,
        ]),
        Line::from(vec![
            Span::styled(
                "  IP Forwarding: ",
                Style::default().fg(colors::TEXT_SECONDARY),
            ),
            ip_fwd_status,
            ip_fwd_modified,
        ]),
        Line::from(vec![
            Span::styled(
                "  DHCP Server:   ",
                Style::default().fg(colors::TEXT_SECONDARY),
            ),
            dhcp_status,
        ]),
        Line::from(vec![
            Span::styled(
                "  NAT-PMP:       ",
                Style::default().fg(colors::TEXT_SECONDARY),
            ),
            natpmp_status,
        ]),
        Line::from(vec![
            Span::styled(
                "  Active States: ",
                Style::default().fg(colors::TEXT_SECONDARY),
            ),
            Span::styled(
                info.pf_state_count.to_string(),
                Style::default()
                    .fg(colors::ACCENT)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
    ];

    // Add sample connections from PF states
    let state_lines: Vec<&str> = info.pf_states.lines().collect();
    let total_states = state_lines.len().saturating_sub(1);
    if total_states > 0 {
        lines.push(Line::from(""));
        let inner_width = area.width.saturating_sub(8) as usize;
        for line in state_lines.iter().skip(1).take(2) {
            let display = if line.len() > inner_width {
                format!("{}...", &line[..inner_width.saturating_sub(3)])
            } else {
                line.to_string()
            };
            lines.push(Line::from(Span::styled(
                format!("    {}", display),
                Style::default().fg(colors::TEXT_SECONDARY),
            )));
        }
    }

    let card = Card::new(Span::styled(" System Status ", styles::card_title()));
    frame.render_widget(card, area);

    let inner = Rect::new(
        area.x + 1,
        area.y + 1,
        area.width.saturating_sub(2),
        area.height.saturating_sub(2),
    );

    let paragraph = Paragraph::new(lines);
    frame.render_widget(paragraph, inner);
}

fn render_pf_rules(frame: &mut Frame, area: Rect, info: &DebugInfo) {
    let card = Card::new(Span::styled(" PF Rules ", styles::card_title()));
    frame.render_widget(card, area);

    let inner = Rect::new(
        area.x + 1,
        area.y + 1,
        area.width.saturating_sub(2),
        area.height.saturating_sub(2),
    );

    let rules: Vec<Line> = info
        .pf_rules
        .lines()
        .take(inner.height as usize)
        .map(|line| {
            let style = if line.starts_with('#') || line.is_empty() {
                Style::default().fg(colors::TEXT_SECONDARY)
            } else if line.starts_with("nat ") || line.starts_with("scrub ") {
                Style::default().fg(colors::ACCENT)
            } else if line.starts_with("pass ") {
                Style::default().fg(colors::SUCCESS)
            } else if line.starts_with("block ") {
                Style::default().fg(colors::ERROR)
            } else {
                Style::default().fg(colors::TEXT_PRIMARY)
            };
            Line::from(Span::styled(format!("  {}", line), style))
        })
        .collect();

    let paragraph = Paragraph::new(rules).wrap(Wrap { trim: false });
    frame.render_widget(paragraph, inner);
}
