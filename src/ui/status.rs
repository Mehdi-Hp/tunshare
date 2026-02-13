//! Status panel, log display, and help bar.

use ratatui::{
    layout::{Alignment, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};

use std::collections::VecDeque;

use crate::app::LogEntry;
use crate::ui::theme::{colors, styles, symbols};
use crate::ui::widgets::Card;

/// Log level for styling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Success,
    Warning,
    Error,
}

impl LogEntry {
    pub fn info(message: impl Into<String>) -> Self {
        Self::new(message, LogLevel::Info)
    }

    pub fn success(message: impl Into<String>) -> Self {
        Self::new(message, LogLevel::Success)
    }

    pub fn warning(message: impl Into<String>) -> Self {
        Self::new(message, LogLevel::Warning)
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self::new(message, LogLevel::Error)
    }

    fn new(message: impl Into<String>, level: LogLevel) -> Self {
        let now = chrono::Local::now();
        Self {
            timestamp: now.format("%H:%M").to_string(), // Shorter format
            message: message.into(),
            level,
        }
    }
}

// Re-export LogLevel for use in app.rs
pub use LogLevel as LogEntryLevel;

/// Render the compact status/log panel.
pub fn render_status_panel(
    frame: &mut Frame,
    area: Rect,
    logs: &VecDeque<LogEntry>,
    max_lines: usize,
    expanded: bool,
) {
    let visible_count = if expanded {
        max_lines
    } else {
        max_lines.min(10) // Collapsed shows 10 lines max
    };

    let visible_logs: Vec<Line> = logs
        .iter()
        .rev()
        .take(visible_count)
        .rev()
        .map(|entry| format_log_entry(entry))
        .collect();

    let log_panel = Paragraph::new(visible_logs)
        .block(
            Block::default()
                .title(Span::styled(" Activity ", styles::card_title()))
                .title_alignment(ratatui::layout::Alignment::Left)
                .borders(Borders::TOP)
                .border_style(styles::border_unfocused()),
        )
        .wrap(Wrap { trim: true });

    frame.render_widget(log_panel, area);

    // Draw item count on the right side of the title
    let count_text = format!(" {} items ", logs.len());
    let count_width = count_text.len() as u16;
    let count_x = area.x + area.width.saturating_sub(count_width + 1);
    if count_x > area.x + 12 {
        let count_para = Paragraph::new(Line::from(Span::styled(
            count_text,
            Style::default().fg(colors::TEXT_SECONDARY),
        )));
        let count_area = Rect::new(count_x, area.y, count_width, 1);
        frame.render_widget(count_para, count_area);
    }
}

/// Format a single log entry with icon.
fn format_log_entry(entry: &LogEntry) -> Line<'static> {
    let (icon, msg_style) = match entry.level {
        LogLevel::Success => (symbols::STATUS_ACTIVE, Style::default().fg(colors::SUCCESS)),
        LogLevel::Info => ("i", Style::default().fg(colors::TEXT_PRIMARY)),
        LogLevel::Warning => (symbols::WARNING, Style::default().fg(colors::WARNING)),
        LogLevel::Error => (symbols::ERROR, Style::default().fg(colors::ERROR)),
    };

    Line::from(vec![
        Span::styled(
            format!("  {}  ", entry.timestamp),
            Style::default().fg(colors::TEXT_SECONDARY),
        ),
        Span::styled(format!("{}  ", icon), msg_style),
        Span::styled(entry.message.clone(), msg_style),
    ])
}

/// Render help text at the bottom with styled keys.
pub fn render_help(frame: &mut Frame, area: Rect, context_help: &str) {
    // Parse and style the help text
    let styled_parts = parse_help_text(context_help);
    let help_line = Line::from(styled_parts);

    let help_text = Paragraph::new(help_line);
    frame.render_widget(help_text, area);
}

/// Parse help text and style keys differently.
fn parse_help_text(text: &str) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    spans.push(Span::raw("  ")); // Left padding

    // Split by double spaces to separate key groups
    let parts: Vec<&str> = text.split("  ").collect();

    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("   ")); // Separator between groups
        }

        // Check if this is a key:action pair
        if let Some(colon_idx) = part.find(':') {
            let key = &part[..colon_idx];
            let action = &part[colon_idx + 1..].trim_start();

            spans.push(Span::styled(key.to_string(), styles::help_key()));
            spans.push(Span::styled(format!(" {}", action), styles::help_text()));
        } else if part.contains('/') {
            // Handle ↑/↓: Navigate format
            let (keys, rest) = if let Some(colon_idx) = part.find(':') {
                (&part[..colon_idx], &part[colon_idx + 1..])
            } else {
                (*part, "")
            };

            spans.push(Span::styled(keys.to_string(), styles::help_key()));
            if !rest.is_empty() {
                spans.push(Span::styled(
                    format!(" {}", rest.trim_start()),
                    styles::help_text(),
                ));
            }
        } else {
            spans.push(Span::styled(part.to_string(), styles::help_text()));
        }
    }

    spans
}

/// Render a loading indicator overlay with moon spinner.
pub fn render_loading_indicator(frame: &mut Frame, area: Rect, message: &str) {
    // Calculate centered popup area
    let popup_width = (message.len() as u16 + 8).min(area.width.saturating_sub(4));
    let popup_height = 3;

    let popup_x = area.x + (area.width.saturating_sub(popup_width)) / 2;
    let popup_y = area.y + (area.height.saturating_sub(popup_height)) / 2;

    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

    // Clear the area behind the popup
    frame.render_widget(Clear, popup_area);

    // Get spinner frame based on time (moon phases)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let spinner_idx = ((now / 150) % symbols::MOON_SPINNER.len() as u128) as usize;
    let spinner = symbols::MOON_SPINNER[spinner_idx];

    let card = Card::empty().border_style(Style::default().fg(colors::ACCENT));
    frame.render_widget(card, popup_area);

    let inner = Rect::new(
        popup_area.x + 1,
        popup_area.y + 1,
        popup_area.width.saturating_sub(2),
        popup_area.height.saturating_sub(2),
    );

    let loading_text = Paragraph::new(Line::from(vec![
        Span::styled(
            format!(" {} ", spinner),
            Style::default()
                .fg(colors::ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(message, Style::default().fg(colors::TEXT_PRIMARY)),
    ]))
    .alignment(Alignment::Center);

    frame.render_widget(loading_text, inner);
}
