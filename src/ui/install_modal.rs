//! Modal that prompts the user to install dnsmasq via Homebrew.
//!
//! Two layouts, selected by `App::brew_installed`:
//!   - brew present → Enter runs `brew install dnsmasq`
//!   - brew absent  → user is sent to brew.sh; Enter is inert

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

/// Card width including borders. Body wraps to `WIDTH - 2 (border) - 6 (indent both sides)`.
const CARD_WIDTH: u16 = 56;
/// Left margin applied to body lines for breathing room past the border.
const INDENT: &str = "   ";

pub fn render_install_dnsmasq(frame: &mut Frame, area: Rect, app: &App) {
    let body: Vec<Line> = if app.brew_installed {
        body_brew_present()
    } else {
        body_brew_absent()
    };

    let card_width = CARD_WIDTH.min(area.width.saturating_sub(4));
    let card_height = (body.len() as u16 + 2).min(area.height.saturating_sub(2));
    let card_x = area.x + (area.width.saturating_sub(card_width)) / 2;
    let card_y = area.y + (area.height.saturating_sub(card_height)) / 2;
    let card_area = Rect::new(card_x, card_y, card_width, card_height);

    frame.render_widget(Clear, area);
    let card = Card::new(Span::styled(" Install dnsmasq ", styles::card_title())).focused(true);
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

fn body_brew_present() -> Vec<Line<'static>> {
    let primary = Style::default().fg(colors::TEXT_PRIMARY);
    let accent = Style::default().fg(colors::ACCENT);
    let muted = Style::default().fg(colors::TEXT_SECONDARY);

    vec![
        blank(),
        indented("tunshare can install dnsmasq for you so it can", primary),
        indented("hand out IPs to LAN clients automatically.", primary),
        blank(),
        indented_with_prefix("$ ", "brew install dnsmasq", muted, accent),
        blank(),
        indented("Takes ~30s on a warm cache. DHCP turns on", muted),
        indented("automatically once the install succeeds.", muted),
        blank(),
        divider(),
        blank(),
        centered_hint("Enter install  ·  Esc cancel"),
    ]
}

fn body_brew_absent() -> Vec<Line<'static>> {
    let primary = Style::default().fg(colors::TEXT_PRIMARY);
    let accent = Style::default().fg(colors::ACCENT);
    let muted = Style::default().fg(colors::TEXT_SECONDARY);

    vec![
        blank(),
        indented("Homebrew isn't installed on this machine, so", primary),
        indented("we can't run brew install dnsmasq for you.", primary),
        blank(),
        indented_with_prefix("→ ", "https://brew.sh", muted, accent),
        blank(),
        indented("Install Homebrew, then re-open this modal —", muted),
        indented("we'll handle the dnsmasq install from there.", muted),
        blank(),
        divider(),
        blank(),
        centered_hint("Esc dismiss"),
    ]
}

// ===== Line builders =====

fn blank() -> Line<'static> {
    Line::from("")
}

fn indented(text: &'static str, style: Style) -> Line<'static> {
    Line::from(vec![Span::raw(INDENT), Span::styled(text, style)])
}

/// Two-segment indented line: e.g. a muted prefix glyph followed by an
/// accented value. Used for the command and the URL rows.
fn indented_with_prefix(
    prefix: &'static str,
    body: &'static str,
    prefix_style: Style,
    body_style: Style,
) -> Line<'static> {
    Line::from(vec![
        Span::raw(INDENT),
        Span::styled(prefix, prefix_style),
        Span::styled(body, body_style),
    ])
}

fn divider() -> Line<'static> {
    // Width matches inner content minus indent on both sides — eyeballed
    // for the 56-wide card. Looks like a hairline rule above the CTA.
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
