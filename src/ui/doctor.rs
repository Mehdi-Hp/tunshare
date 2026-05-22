//! Doctor screen — grouped diagnostic checklist with inline values,
//! always-visible hint for the focused row, and a status summary.

use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Clear, Paragraph, Wrap},
    Frame,
};

use crate::app::App;
use crate::doctor::{CheckResult, CheckStatus, CheckSummary};
use crate::ui::theme::{colors, styles, symbols};
use crate::ui::widgets::Card;

pub fn render_doctor(frame: &mut Frame, area: Rect, app: &App) {
    frame.render_widget(Clear, area);

    let results = &app.doctor.results;
    let card_width = area.width.saturating_sub(4).min(80);
    let card_x = area.x + (area.width.saturating_sub(card_width)) / 2;

    // Empty / loading state: compact card with the spinner message.
    if results.is_empty() {
        let card_height = 3u16.min(area.height);
        let card_y = area.y + (area.height.saturating_sub(card_height)) / 2;
        let card_area = Rect::new(card_x, card_y, card_width, card_height);
        let card = Card::new(Span::styled(" Doctor ", styles::card_title())).focused(true);
        frame.render_widget(card, card_area);
        let inner = Rect::new(
            card_area.x + 3,
            card_area.y + 1,
            card_area.width.saturating_sub(6),
            1,
        );
        let line = Line::from(Span::styled(
            "Running diagnostic checks...",
            Style::default().fg(colors::TEXT_SECONDARY),
        ));
        frame.render_widget(Paragraph::new(line), inner);
        return;
    }

    // Inner row budget (top to bottom):
    //   1  subtitle
    //   1  blank
    //   N  list rows
    //   1  blank
    //   2  hint
    //   1  blank
    //   1  summary
    //   1  bottom padding
    const HINT_HEIGHT: u16 = 2;
    const SUMMARY_HEIGHT: u16 = 1;
    const NON_LIST_HEIGHT: u16 = 1 + 1 + 1 + HINT_HEIGHT + 1 + SUMMARY_HEIGHT + 1;

    // Build display rows up front so we can size the card to fit content.
    let mut display_rows: Vec<DisplayRow> = Vec::new();
    let mut current_group: &str = "";
    for (i, r) in results.iter().enumerate() {
        if r.group != current_group {
            if !current_group.is_empty() {
                display_rows.push(DisplayRow::Blank);
            }
            display_rows.push(DisplayRow::Header(r.group));
            current_group = r.group;
        }
        display_rows.push(DisplayRow::Check { check_idx: i });
    }

    // Card hugs content. If the area is shorter than that, cap to fit.
    let desired_inner_height = NON_LIST_HEIGHT + display_rows.len() as u16;
    let max_inner_height = area.height.saturating_sub(2);
    let inner_height = desired_inner_height.min(max_inner_height);
    let card_height = inner_height + 2;
    let card_y = area.y + (area.height.saturating_sub(card_height)) / 2;
    let card_area = Rect::new(card_x, card_y, card_width, card_height);

    let card = Card::new(Span::styled(" Doctor ", styles::card_title())).focused(true);
    frame.render_widget(card, card_area);

    let inner = Rect::new(
        card_area.x + 3,
        card_area.y + 1,
        card_area.width.saturating_sub(6),
        card_area.height.saturating_sub(2),
    );

    // Inner row offsets (see NON_LIST_HEIGHT comment above for the budget).
    let subtitle_y = inner.y;
    let list_y = subtitle_y + 2; // subtitle + 1 blank
    let list_height = inner.height.saturating_sub(NON_LIST_HEIGHT);

    let subtitle = Line::from(Span::styled(
        "Diagnose why sharing might not work",
        Style::default().fg(colors::TEXT_SECONDARY),
    ));
    let subtitle_area = Rect::new(inner.x, subtitle_y, inner.width, 1);
    frame.render_widget(Paragraph::new(subtitle), subtitle_area);

    // Scroll so the row containing the selected check stays in view.
    let selected_display = display_rows
        .iter()
        .position(
            |r| matches!(r, DisplayRow::Check { check_idx } if *check_idx == app.doctor.selected),
        )
        .unwrap_or(0);
    let visible = list_height as usize;
    let scroll_start = selected_display.saturating_sub(visible.saturating_sub(1));

    for (offset, row) in display_rows
        .iter()
        .skip(scroll_start)
        .take(visible)
        .enumerate()
    {
        let y = list_y + offset as u16;
        match row {
            DisplayRow::Blank => {}
            DisplayRow::Header(g) => render_group_header(frame, inner, y, g),
            DisplayRow::Check { check_idx } => {
                let r = &results[*check_idx];
                let is_selected = *check_idx == app.doctor.selected;
                render_check_row(frame, inner, y, r, is_selected);
            }
        }
    }

    // Always-visible hint pane for the focused row. One blank row above
    // separates it from the list.
    let hint_y = list_y + list_height + 1;
    let selected = &results[app.doctor.selected.min(results.len() - 1)];
    render_hint(frame, inner, hint_y, selected);

    // Summary line, leaving 1 row of bottom padding below it.
    let summary_y = inner.y + inner.height.saturating_sub(2);
    render_summary(frame, inner, summary_y, results);
}

enum DisplayRow<'a> {
    Blank,
    Header(&'a str),
    Check { check_idx: usize },
}

fn render_group_header(frame: &mut Frame, inner: Rect, y: u16, group: &str) {
    let line = Line::from(Span::styled(
        group.to_string(),
        Style::default()
            .fg(colors::ACCENT)
            .add_modifier(Modifier::BOLD),
    ));
    let area = Rect::new(inner.x, y, inner.width, 1);
    frame.render_widget(Paragraph::new(line), area);
}

fn render_check_row(frame: &mut Frame, inner: Rect, y: u16, r: &CheckResult, is_selected: bool) {
    let (icon, icon_style) = match &r.status {
        CheckStatus::Pass => ("\u{2713}", Style::default().fg(colors::SUCCESS)),
        CheckStatus::Warn { .. } => (symbols::WARNING, Style::default().fg(colors::WARNING)),
        CheckStatus::Fail { .. } => (symbols::ERROR, Style::default().fg(colors::ERROR)),
    };

    let name_style = if is_selected {
        styles::selected()
    } else {
        styles::unselected()
    };

    // Prefix: 3 chars. Selected row shows the cursor; others show indent.
    let prefix = if is_selected {
        format!(" {} ", symbols::SELECTED)
    } else {
        "   ".to_string()
    };

    let value_str = r.detail.lines().next().unwrap_or("").to_string();

    let value_style = Style::default().fg(colors::TEXT_SECONDARY);

    // Layout: prefix + name <gap> [value " "] icon
    // Icon always lands in the rightmost column.
    let prefix_w = prefix.chars().count() as u16;
    let name_w = r.name.chars().count() as u16;
    let icon_w: u16 = 1;
    let value_pad_w: u16 = if value_str.is_empty() { 0 } else { 1 };
    let left_used = prefix_w + name_w;
    let available_for_value = inner
        .width
        .saturating_sub(left_used)
        .saturating_sub(icon_w + value_pad_w)
        .saturating_sub(1); // at least 1 space between name and value/icon
    let value_truncated = truncate_to(&value_str, available_for_value as usize);
    let value_w = value_truncated.chars().count() as u16;
    let gap = inner
        .width
        .saturating_sub(left_used + value_w + value_pad_w + icon_w);

    let mut spans = vec![
        Span::styled(prefix, name_style),
        Span::styled(r.name.clone(), name_style),
        Span::raw(" ".repeat(gap as usize)),
    ];
    if !value_truncated.is_empty() {
        spans.push(Span::styled(value_truncated, value_style));
        spans.push(Span::raw(" "));
    }
    spans.push(Span::styled(icon.to_string(), icon_style));

    let area = Rect::new(inner.x, y, inner.width, 1);
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn render_hint(frame: &mut Frame, inner: Rect, y: u16, r: &CheckResult) {
    let area = Rect::new(inner.x, y, inner.width, 2);
    let (marker_style, text) = match &r.status {
        // Pass rows don't need a hint — the inline value already says it all.
        CheckStatus::Pass => return,
        CheckStatus::Warn { hint } => (Style::default().fg(colors::WARNING), hint.clone()),
        CheckStatus::Fail { hint } => (Style::default().fg(colors::ERROR), hint.clone()),
    };
    if text.is_empty() {
        return;
    }
    let line = Line::from(vec![
        Span::styled("▸ ", marker_style),
        Span::styled(text, Style::default().fg(colors::TEXT_PRIMARY)),
    ]);
    frame.render_widget(Paragraph::new(line).wrap(Wrap { trim: false }), area);
}

fn render_summary(frame: &mut Frame, inner: Rect, y: u16, results: &[CheckResult]) {
    let s = CheckSummary::from_results(results);
    let mut spans: Vec<Span> = vec![Span::styled(
        format!("\u{2713} {} pass", s.pass),
        Style::default().fg(colors::SUCCESS),
    )];
    if s.warn > 0 {
        spans.push(Span::raw("   "));
        spans.push(Span::styled(
            format!("{} {} warn", symbols::WARNING, s.warn),
            Style::default().fg(colors::WARNING),
        ));
    }
    if s.fail > 0 {
        spans.push(Span::raw("   "));
        spans.push(Span::styled(
            format!("{} {} fail", symbols::ERROR, s.fail),
            Style::default().fg(colors::ERROR),
        ));
    }
    spans.push(Span::raw("   "));
    spans.push(Span::styled(
        format!("{} total", s.total()),
        Style::default().fg(colors::TEXT_SECONDARY),
    ));

    let area = Rect::new(inner.x, y, inner.width, 1);
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// Truncate `s` to at most `max` chars, appending `…` when cut.
fn truncate_to(s: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    let count = s.chars().count();
    if count <= max {
        return s.to_string();
    }
    let take = max.saturating_sub(1);
    let mut out: String = s.chars().take(take).collect();
    out.push('\u{2026}');
    out
}
