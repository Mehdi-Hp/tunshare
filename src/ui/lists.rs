//! Lists screen — independent blocklist / allowlist toggles.

use std::time::SystemTime;

use ratatui::{
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Clear, Paragraph},
    Frame,
};

use crate::app::App;
use crate::ui::theme::{colors, styles, symbols};
use crate::ui::widgets::Card;

pub fn render_lists(frame: &mut Frame, area: Rect, app: &App) {
    frame.render_widget(Clear, area);

    let block_on = app.lists.block.enabled;
    let allow_on = app.lists.allow.enabled;
    let block_detail = format_detail(app.lists_ui.block_count, app.lists_ui.block_fetched);
    let allow_detail = format_detail(app.lists_ui.allow_count, app.lists_ui.allow_fetched);

    let card_width = area.width.saturating_sub(4).min(64);
    let card_height = 11u16.min(area.height.saturating_sub(2));
    let card_x = area.x + (area.width.saturating_sub(card_width)) / 2;
    let card_y = area.y + (area.height.saturating_sub(card_height)) / 2;
    let card_area = Rect::new(card_x, card_y, card_width, card_height);

    let card = Card::new(Span::styled(" Lists ", styles::card_title())).focused(true);
    frame.render_widget(card, card_area);

    let inner = Rect::new(
        card_area.x + 1,
        card_area.y + 1,
        card_area.width.saturating_sub(2),
        card_area.height.saturating_sub(2),
    );

    let mut y = inner.y + 1;
    paint_item(
        frame,
        inner,
        y,
        0,
        app.lists_ui.selected,
        "Blocklist",
        &block_detail,
        block_on,
    );
    y += 3;
    paint_item(
        frame,
        inner,
        y,
        1,
        app.lists_ui.selected,
        "Allowlist",
        &allow_detail,
        allow_on,
    );

    let hint_y = inner.y + inner.height.saturating_sub(1);
    let hint = if app.is_sharing() {
        "Enter toggle · r refresh (live) · Esc back"
    } else {
        "Enter toggle · r refresh · Esc back"
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(hint, styles::hint()))),
        Rect::new(inner.x, hint_y, inner.width, 1),
    );
}

#[allow(clippy::too_many_arguments)]
fn paint_item(
    frame: &mut Frame,
    inner: Rect,
    y: u16,
    idx: usize,
    selected: usize,
    title: &str,
    detail: &str,
    on: bool,
) {
    if y >= inner.y + inner.height {
        return;
    }
    let is_selected = idx == selected;
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
    let (badge_text, badge_style) = if on {
        (
            format!("{} ON", symbols::STATUS_ACTIVE),
            styles::status_on(),
        )
    } else {
        (
            format!("{} OFF", symbols::STATUS_INACTIVE),
            styles::status_off(),
        )
    };

    let used = 5 + title.chars().count() as u16;
    let gap = inner
        .width
        .saturating_sub(used + badge_text.chars().count() as u16 + 1);
    let line = Line::from(vec![
        Span::styled(prefix, style),
        Span::styled(title.to_string(), style),
        Span::raw(" ".repeat(gap as usize)),
        Span::styled(badge_text, if is_selected { style } else { badge_style }),
    ]);
    frame.render_widget(Paragraph::new(line), Rect::new(inner.x, y, inner.width, 1));

    if y + 1 < inner.y + inner.height {
        let detail_line = Line::from(vec![
            Span::raw("     "),
            Span::styled(
                detail.to_string(),
                Style::default().fg(colors::TEXT_SECONDARY),
            ),
        ]);
        frame.render_widget(
            Paragraph::new(detail_line),
            Rect::new(inner.x, y + 1, inner.width, 1),
        );
    }
}

fn format_detail(count: usize, fetched: Option<SystemTime>) -> String {
    format!("{count} names · {}", fetched_label(fetched))
}

fn fetched_label(when: Option<SystemTime>) -> String {
    let Some(when) = when else {
        return "not fetched".into();
    };
    let Ok(age) = SystemTime::now().duration_since(when) else {
        return "just now".into();
    };
    let secs = age.as_secs();
    if secs < 60 {
        "just now".into()
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86400)
    }
}
