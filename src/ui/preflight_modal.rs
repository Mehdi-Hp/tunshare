//! Modal shown when `Start VPN Sharing` was selected but at least one
//! prerequisite is missing (no VPN interface, no wired LAN interface, or
//! both). Surfaces the missing items and offers Rescan / Doctor / Cancel.

use ratatui::{
    layout::{Alignment, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Clear, Paragraph},
    Frame,
};

use crate::app::App;
use crate::ui::theme::{colors, styles, symbols};
use crate::ui::widgets::Card;

const CARD_WIDTH: u16 = 60;
const INDENT: &str = "   ";

pub fn render_preflight(frame: &mut Frame, area: Rect, app: &App) {
    let vpn_missing = app.vpn_interfaces.is_empty();
    let lan_missing = app.lan_interfaces.is_empty();

    let body = build_body(vpn_missing, lan_missing);

    let card_width = CARD_WIDTH.min(area.width.saturating_sub(4));
    let card_height = (body.len() as u16 + 2).min(area.height.saturating_sub(2));
    let card_x = area.x + (area.width.saturating_sub(card_width)) / 2;
    let card_y = area.y + (area.height.saturating_sub(card_height)) / 2;
    let card_area = Rect::new(card_x, card_y, card_width, card_height);

    frame.render_widget(Clear, area);
    let card = Card::new(Span::styled(" Not ready to share ", styles::card_title())).focused(true);
    frame.render_widget(card, card_area);

    let inner = Rect::new(
        card_area.x + 1,
        card_area.y + 1,
        card_area.width.saturating_sub(2),
        card_area.height.saturating_sub(2),
    );

    for (i, line) in body.into_iter().enumerate() {
        let y = inner.y + i as u16;
        if y >= inner.y + inner.height {
            break;
        }
        let row_area = Rect::new(inner.x, y, inner.width, 1);
        frame.render_widget(Paragraph::new(line), row_area);
    }
}

fn build_body(vpn_missing: bool, lan_missing: bool) -> Vec<Line<'static>> {
    let primary = Style::default().fg(colors::TEXT_PRIMARY);
    let muted = Style::default().fg(colors::TEXT_SECONDARY);
    let error = Style::default().fg(colors::ERROR);

    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(blank());
    lines.push(indented("Connect the following before sharing:", primary));
    lines.push(blank());

    if vpn_missing {
        lines.push(indented_with_prefix(
            &format!("{} ", symbols::ERROR),
            "VPN connection",
            error,
            primary,
        ));
        lines.push(indented(
            "  Open your VPN client app and connect, then",
            muted,
        ));
        lines.push(indented("  rescan from this screen.", muted));
        lines.push(blank());
    }

    if lan_missing {
        lines.push(indented_with_prefix(
            &format!("{} ", symbols::ERROR),
            "Wired LAN adapter",
            error,
            primary,
        ));
        lines.push(indented(
            "  Wi-Fi is excluded by design. Connect a wired",
            muted,
        ));
        lines.push(indented("  ethernet interface, then rescan.", muted));
        lines.push(blank());
    }

    lines.push(divider());
    lines.push(blank());
    lines.push(centered_hint("r rescan  ·  d doctor  ·  Esc cancel"));

    lines
}

// ===== Line builders (mirror src/ui/install_modal.rs) =====

fn blank() -> Line<'static> {
    Line::from("")
}

fn indented(text: &'static str, style: Style) -> Line<'static> {
    Line::from(vec![Span::raw(INDENT), Span::styled(text, style)])
}

fn indented_with_prefix(
    prefix: &str,
    body: &'static str,
    prefix_style: Style,
    body_style: Style,
) -> Line<'static> {
    Line::from(vec![
        Span::raw(INDENT),
        Span::styled(prefix.to_string(), prefix_style),
        Span::styled(body, body_style),
    ])
}

fn divider() -> Line<'static> {
    let width = (CARD_WIDTH as usize).saturating_sub(2 + INDENT.len() * 2);
    let dashes: String = symbols::SEPARATOR_CHAR.repeat(width);
    Line::from(vec![
        Span::raw(INDENT),
        Span::styled(dashes, Style::default().fg(colors::TEXT_SECONDARY)),
    ])
}

fn centered_hint(text: &'static str) -> Line<'static> {
    Line::from(Span::styled(text, styles::hint())).alignment(Alignment::Center)
}
