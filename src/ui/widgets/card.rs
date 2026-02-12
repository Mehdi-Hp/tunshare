//! Card widget with rounded corners.
//!
//! Provides a modern, lazygit-style card component with:
//! - Rounded corners (╭╮╰╯)
//! - Optional title
//! - Customizable border colors

use ratatui::{buffer::Buffer, layout::Rect, style::Style, text::Span, widgets::Widget};

use crate::ui::theme::{borders, colors, styles};

/// A card widget with rounded corners.
pub struct Card<'a> {
    /// Title displayed in the top border.
    title: Option<Span<'a>>,
    /// Title alignment within the top border.
    title_alignment: TitleAlignment,
    /// Border style.
    border_style: Style,
    /// Whether this card is focused.
    focused: bool,
    /// Optional item count displayed on the right side of title bar.
    item_count: Option<usize>,
}

/// Alignment for card title.
#[derive(Debug, Clone, Copy, Default)]
pub enum TitleAlignment {
    #[default]
    Left,
}

impl<'a> Card<'a> {
    /// Create a simple card with a title.
    pub fn new(title: impl Into<Span<'a>>) -> Self {
        Self {
            title: Some(title.into()),
            title_alignment: TitleAlignment::Left,
            border_style: styles::border_unfocused(),
            focused: false,
            item_count: None,
        }
    }

    /// Create an empty card without a title.
    pub fn empty() -> Self {
        Self {
            title: None,
            title_alignment: TitleAlignment::Left,
            border_style: styles::border_unfocused(),
            focused: false,
            item_count: None,
        }
    }

    /// Set whether this card is focused.
    pub fn focused(mut self, focused: bool) -> Self {
        self.focused = focused;
        self.border_style = if focused {
            styles::border_focused()
        } else {
            styles::border_unfocused()
        };
        self
    }

    /// Set custom border style.
    pub fn border_style(mut self, style: Style) -> Self {
        self.border_style = style;
        self
    }

    /// Set item count to display.
    pub fn item_count(mut self, count: usize) -> Self {
        self.item_count = Some(count);
        self
    }
}

impl Widget for Card<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width < 2 || area.height < 2 {
            return;
        }

        let border_style = self.border_style;

        // Draw corners
        buf.set_string(area.x, area.y, borders::TOP_LEFT, border_style);
        buf.set_string(
            area.x + area.width.saturating_sub(1),
            area.y,
            borders::TOP_RIGHT,
            border_style,
        );
        buf.set_string(
            area.x,
            area.y + area.height.saturating_sub(1),
            borders::BOTTOM_LEFT,
            border_style,
        );
        buf.set_string(
            area.x + area.width.saturating_sub(1),
            area.y + area.height.saturating_sub(1),
            borders::BOTTOM_RIGHT,
            border_style,
        );

        // Draw horizontal borders
        for x in (area.x + 1)..(area.x + area.width.saturating_sub(1)) {
            buf.set_string(x, area.y, borders::HORIZONTAL, border_style);
            buf.set_string(
                x,
                area.y + area.height.saturating_sub(1),
                borders::HORIZONTAL,
                border_style,
            );
        }

        // Draw vertical borders
        for y in (area.y + 1)..(area.y + area.height.saturating_sub(1)) {
            buf.set_string(area.x, y, borders::VERTICAL, border_style);
            buf.set_string(
                area.x + area.width.saturating_sub(1),
                y,
                borders::VERTICAL,
                border_style,
            );
        }

        // Draw title if present
        if let Some(title) = self.title {
            let title_str = format!(" {} ", title.content);
            let title_width = title_str.chars().count() as u16;
            let available_width = area.width.saturating_sub(4);

            if title_width <= available_width {
                let title_x = match self.title_alignment {
                    TitleAlignment::Left => area.x + 1,
                };

                // Use title style merged with border style
                let title_style = title.style;
                buf.set_string(title_x, area.y, &title_str, title_style);
            }
        }

        // Draw item count if present
        if let Some(count) = self.item_count {
            let count_str = format!(" {} items ", count);
            let count_width = count_str.len() as u16;
            if count_width + 2 < area.width {
                let count_x = area.x + area.width.saturating_sub(count_width + 1);
                buf.set_string(
                    count_x,
                    area.y,
                    &count_str,
                    Style::default().fg(colors::TEXT_SECONDARY),
                );
            }
        }
    }
}
