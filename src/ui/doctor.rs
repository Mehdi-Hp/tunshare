//! Doctor screen — renders the diagnostic checklist with status icons,
//! an optional expanded detail/hint pane for the selected row, and a
//! summary line.

use ratatui::{
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Clear, Paragraph, Wrap},
    Frame,
};

use crate::app::App;
use crate::doctor::{CheckStatus, CheckSummary};
use crate::ui::theme::{colors, styles, symbols};
use crate::ui::widgets::Card;

pub fn render_doctor(frame: &mut Frame, area: Rect, app: &App) {
    frame.render_widget(Clear, area);

    let card_width = area.width.saturating_sub(4).min(80);
    let card_x = area.x + (area.width.saturating_sub(card_width)) / 2;
    let card_height = area.height.saturating_sub(2);
    let card_y = area.y + 1;
    let card_area = Rect::new(card_x, card_y, card_width, card_height);

    let card = Card::new(Span::styled(" Doctor ", styles::card_title())).focused(true);
    frame.render_widget(card, card_area);

    let inner = Rect::new(
        card_area.x + 2,
        card_area.y + 1,
        card_area.width.saturating_sub(4),
        card_area.height.saturating_sub(2),
    );

    let results = &app.doctor.results;

    if results.is_empty() {
        // First-run / pending state. The loading overlay is rendered by
        // main.rs via render_loading_indicator, so we just show a hint.
        let line = Line::from(Span::styled(
            "Running diagnostic checks...",
            Style::default().fg(colors::TEXT_SECONDARY),
        ));
        frame.render_widget(Paragraph::new(line), inner);
        return;
    }

    // Reserve last 1 line for summary; 4 lines for detail when expanded.
    let summary_height: u16 = 1;
    let detail_height: u16 = if app.doctor.expanded { 5 } else { 0 };
    let list_height = inner
        .height
        .saturating_sub(summary_height + detail_height + 1);
    let list_area = Rect::new(inner.x, inner.y, inner.width, list_height);

    // Render the checklist. Scroll so the selected row is always visible.
    let visible = list_area.height as usize;
    let start = app
        .doctor
        .selected
        .saturating_sub(visible.saturating_sub(1));
    for (offset, (i, result)) in results
        .iter()
        .enumerate()
        .skip(start)
        .take(visible)
        .enumerate()
    {
        let y = list_area.y + offset as u16;
        let is_selected = i == app.doctor.selected;

        let (icon, icon_style) = match &result.status {
            CheckStatus::Pass => ("\u{2713}", Style::default().fg(colors::SUCCESS)),
            CheckStatus::Warn { .. } => (symbols::WARNING, Style::default().fg(colors::WARNING)),
            CheckStatus::Fail { .. } => (symbols::ERROR, Style::default().fg(colors::ERROR)),
        };

        let name_style = if is_selected {
            styles::selected()
        } else {
            styles::unselected()
        };

        let prefix = if is_selected {
            format!("  {}  ", symbols::SELECTED)
        } else {
            "     ".to_string()
        };

        let line = Line::from(vec![
            Span::styled(prefix, name_style),
            Span::styled(format!("{icon} "), icon_style),
            Span::styled(result.name.clone(), name_style),
        ]);
        let row = Rect::new(list_area.x, y, list_area.width, 1);
        frame.render_widget(Paragraph::new(line), row);
    }

    // Detail / hint panel for the selected row, when expanded.
    if detail_height > 0 {
        let detail_area = Rect::new(
            inner.x,
            list_area.y + list_area.height,
            inner.width,
            detail_height,
        );
        let selected = &results[app.doctor.selected.min(results.len() - 1)];
        let mut lines: Vec<Line> = Vec::new();
        if !selected.detail.is_empty() {
            for d in selected.detail.lines() {
                lines.push(Line::from(Span::styled(
                    format!("  {d}"),
                    Style::default().fg(colors::TEXT_SECONDARY),
                )));
            }
        }
        match &selected.status {
            CheckStatus::Warn { hint } | CheckStatus::Fail { hint } => {
                lines.push(Line::from(vec![
                    Span::styled("  hint: ", styles::hint()),
                    Span::styled(hint.clone(), Style::default().fg(colors::ACCENT)),
                ]));
            }
            CheckStatus::Pass => {}
        }
        frame.render_widget(
            Paragraph::new(lines).wrap(Wrap { trim: false }),
            detail_area,
        );
    }

    // Summary line.
    let summary = CheckSummary::from_results(results);
    let summary_area = Rect::new(
        inner.x,
        inner.y + inner.height.saturating_sub(1),
        inner.width,
        1,
    );
    let summary_line = Line::from(vec![
        Span::styled(
            format!("{} checks · ", summary.total()),
            Style::default().fg(colors::TEXT_SECONDARY),
        ),
        Span::styled(
            format!("{} pass", summary.pass),
            Style::default().fg(colors::SUCCESS),
        ),
        Span::styled(" · ", Style::default().fg(colors::TEXT_SECONDARY)),
        Span::styled(
            format!("{} warn", summary.warn),
            Style::default().fg(colors::WARNING),
        ),
        Span::styled(" · ", Style::default().fg(colors::TEXT_SECONDARY)),
        Span::styled(
            format!("{} fail", summary.fail),
            Style::default().fg(colors::ERROR),
        ),
    ]);
    frame.render_widget(Paragraph::new(summary_line), summary_area);
}
