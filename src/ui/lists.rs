//! Domain filters screen — two independently scrolling columns.

use std::time::SystemTime;

use ratatui::{
    layout::{Constraint, Flex, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Clear, Paragraph},
    Frame,
};

use crate::app::{App, FilterJob, FilterRow};
use crate::config::ListSetting;
use crate::ui::theme::{borders, colors, styles, symbols};
use crate::ui::widgets::Card;

pub fn render_lists(frame: &mut Frame, area: Rect, app: &App) {
    frame.render_widget(Clear, area);

    let outer_width = area.width.saturating_sub(2).max(40);
    let outer_height = area.height.saturating_sub(1).max(10);
    let outer_x = area.x + (area.width.saturating_sub(outer_width)) / 2;
    let outer_y = area.y;
    let outer = Rect::new(outer_x, outer_y, outer_width, outer_height);

    let [title_area, subtitle_area, _, columns_area, _, hint_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(outer);

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "Domain filters",
            styles::card_title(),
        ))),
        title_area,
    );
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "Block answers NXDOMAIN. WAN bypass sends listed names around the VPN.",
            styles::hint(),
        ))),
        subtitle_area,
    );

    if app.lists_ui.adding.is_some() {
        render_add_overlay(frame, columns_area, app);
        return;
    }

    let [block_area, allow_area] = Layout::horizontal([Constraint::Fill(1), Constraint::Fill(1)])
        .flex(Flex::Start)
        .spacing(1)
        .areas(columns_area);

    render_column(frame, block_area, app, FilterJob::Block);
    render_column(frame, allow_area, app, FilterJob::Allow);

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "Enter toggle · Tab/←→ column · x remove custom · r refresh · Esc back",
            styles::hint(),
        ))),
        hint_area,
    );
}

fn render_column(frame: &mut Frame, area: Rect, app: &App, job: FilterJob) {
    if area.width < 12 || area.height < 4 {
        return;
    }

    let focused = app.lists_ui.focus == job && app.lists_ui.adding.is_none();
    let (title, enabled, count, fetched) = match job {
        FilterJob::Block => (
            " Block ",
            app.lists.block.enabled,
            app.lists_ui.block_count,
            app.lists_ui.block_fetched,
        ),
        FilterJob::Allow => (
            " WAN bypass ",
            app.lists.allow.enabled,
            app.lists_ui.allow_count,
            app.lists_ui.allow_fetched,
        ),
    };

    frame.render_widget(
        Card::new(Span::styled(title, styles::card_title())).focused(focused),
        area,
    );

    let inner = Rect::new(
        area.x + 1,
        area.y + 1,
        area.width.saturating_sub(2),
        area.height.saturating_sub(2),
    );
    if inner.height == 0 || inner.width == 0 {
        return;
    }

    let list_area = Rect::new(
        inner.x,
        inner.y,
        inner.width.saturating_sub(1),
        inner.height,
    );
    let rows = app.column_rows(job);
    let selected = match job {
        FilterJob::Block => app.lists_ui.block_selected,
        FilterJob::Allow => app.lists_ui.allow_selected,
    }
    .min(rows.len().saturating_sub(1));
    let viewport = list_area.height as usize;
    let scroll = visible_scroll(selected, rows.len(), viewport);
    let paint = ColumnPaint {
        focused,
        job_enabled: enabled,
        count,
        fetched,
    };

    for (y, (idx, row)) in (list_area.y..).zip(rows.iter().enumerate().skip(scroll).take(viewport))
    {
        paint_row(frame, list_area, y, *row, idx == selected, paint, app);
    }

    paint_scrollbar(frame, inner, scroll, rows.len(), viewport);
}

#[derive(Clone, Copy)]
struct ColumnPaint {
    focused: bool,
    job_enabled: bool,
    count: usize,
    fetched: Option<SystemTime>,
}

fn paint_row(
    frame: &mut Frame,
    inner: Rect,
    y: u16,
    row: FilterRow,
    is_selected: bool,
    paint: ColumnPaint,
    app: &App,
) {
    let active = is_selected && paint.focused;
    let cursor = if active {
        format!("{} ", symbols::SELECTED)
    } else {
        "  ".to_string()
    };
    let style = if active {
        styles::selected()
    } else {
        styles::unselected()
    };

    match row {
        FilterRow::Job(_) => render_labeled_row(
            frame,
            Rect::new(inner.x, y, inner.width, 1),
            &cursor,
            if paint.job_enabled {
                "Enabled"
            } else {
                "Disabled"
            },
            style,
            Some(on_off_badge(paint.job_enabled, active)),
            (!active).then_some(format_detail(paint.count, paint.fetched)),
        ),
        FilterRow::Source { job, index } => {
            let Some(source) = setting_for(app, job).sources.get(index) else {
                return;
            };
            render_labeled_row(
                frame,
                Rect::new(inner.x, y, inner.width, 1),
                &cursor,
                &source.label(),
                style,
                Some(on_off_badge(source.enabled, active)),
                None,
            );
        }
        FilterRow::Add { .. } => render_labeled_row(
            frame,
            Rect::new(inner.x, y, inner.width, 1),
            &cursor,
            "Add source…",
            style,
            None,
            None,
        ),
    }
}

fn on_off_badge(on: bool, selected: bool) -> (String, Style) {
    let text = if on {
        format!("{} ON", symbols::STATUS_ACTIVE)
    } else {
        format!("{} OFF", symbols::STATUS_INACTIVE)
    };
    let style = if selected {
        styles::selected()
    } else if on {
        styles::status_on()
    } else {
        styles::status_off()
    };
    (text, style)
}

fn render_labeled_row(
    frame: &mut Frame,
    area: Rect,
    cursor: &str,
    label: &str,
    label_style: Style,
    badge: Option<(String, Style)>,
    detail: Option<String>,
) {
    let mut spans = vec![
        Span::styled(cursor.to_string(), label_style),
        Span::styled(
            truncate(label, area.width.saturating_sub(12) as usize),
            label_style,
        ),
    ];
    if let Some((badge_text, badge_style)) = badge {
        let used =
            cursor.chars().count() + spans[1].content.chars().count() + badge_text.chars().count();
        let mut gap = area.width.saturating_sub(used as u16 + 1);
        if let Some(detail) = detail {
            let detail_text = format!("  {detail}");
            if (detail_text.chars().count() as u16) < gap {
                gap -= detail_text.chars().count() as u16;
                spans.push(Span::styled(
                    detail_text,
                    Style::default().fg(colors::TEXT_SECONDARY),
                ));
            }
        }
        spans.push(Span::raw(" ".repeat(gap as usize)));
        spans.push(Span::styled(badge_text, badge_style));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn paint_scrollbar(frame: &mut Frame, inner: Rect, scroll: usize, total: usize, viewport: usize) {
    if total <= viewport || inner.width == 0 || inner.height == 0 {
        return;
    }
    let track = inner.height as usize;
    let thumb_len = ((viewport * track) / total).max(1);
    let max_thumb_start = track.saturating_sub(thumb_len);
    let max_scroll = total.saturating_sub(viewport);
    let thumb_start = (scroll * max_thumb_start)
        .checked_div(max_scroll)
        .unwrap_or(0);
    let x = inner.x + inner.width.saturating_sub(1);
    for i in 0..track {
        let glyph = if i >= thumb_start && i < thumb_start + thumb_len {
            "▐"
        } else {
            borders::VERTICAL
        };
        let style = if i >= thumb_start && i < thumb_start + thumb_len {
            styles::border_focused()
        } else {
            styles::border_unfocused()
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(glyph, style))),
            Rect::new(x, inner.y + i as u16, 1, 1),
        );
    }
}

fn setting_for(app: &App, job: FilterJob) -> &ListSetting {
    match job {
        FilterJob::Block => &app.lists.block,
        FilterJob::Allow => &app.lists.allow,
    }
}

fn render_add_overlay(frame: &mut Frame, area: Rect, app: &App) {
    let job = match app.lists_ui.adding {
        Some(FilterJob::Block) => "Block",
        Some(FilterJob::Allow) => "WAN bypass",
        None => "list",
    };
    let width = area.width.min(56);
    let height = 7.min(area.height);
    let overlay = Rect::new(
        area.x + (area.width.saturating_sub(width)) / 2,
        area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    );
    frame.render_widget(Clear, overlay);
    frame.render_widget(
        Card::new(Span::styled(
            format!(" Add to {job} "),
            styles::card_title(),
        ))
        .focused(true),
        overlay,
    );

    let inner = Rect::new(
        overlay.x + 2,
        overlay.y + 1,
        overlay.width.saturating_sub(4),
        overlay.height.saturating_sub(2),
    );
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "Paste an http:// or https:// URL",
            Style::default().fg(colors::TEXT_SECONDARY),
        ))),
        Rect::new(inner.x, inner.y, inner.width, 1),
    );

    let input_display = format!("{}█", app.lists_ui.input_buffer);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("URL: ", Style::default().fg(colors::TEXT_SECONDARY)),
            Span::styled(
                input_display,
                Style::default()
                    .fg(colors::TEXT_PRIMARY)
                    .add_modifier(Modifier::BOLD),
            ),
        ])),
        Rect::new(inner.x, inner.y + 2, inner.width, 1),
    );
}

fn visible_scroll(selected: usize, total: usize, height: usize) -> usize {
    if total <= height {
        return 0;
    }
    let max_scroll = total.saturating_sub(height);
    selected
        .saturating_sub(height.saturating_sub(1) / 2)
        .min(max_scroll)
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

fn truncate(text: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    if text.chars().count() <= max {
        return text.to_string();
    }
    let keep = max.saturating_sub(1);
    let mut s: String = text.chars().take(keep).collect();
    s.push('…');
    s
}
