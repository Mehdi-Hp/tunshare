//! tunshare - VPN Sharing TUI for macOS
//!
//! Routes internet traffic through a VPN and shares it via LAN to connected devices.
//! Uses macOS's pf (packet filter) firewall for NAT.

mod app;
mod error;
mod session;
mod system;
mod ui;

use std::io;
use std::panic;
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    Terminal,
};

use app::{App, AppState};
use ui::{
    debug::render_debug_panel,
    interface_select::{render_lan_selection, render_vpn_selection},
    main_menu::{
        render_connection_info, render_dns_edit, render_header, render_main_menu, render_separator,
    },
    status::{render_help, render_loading_indicator, render_status_panel},
};

#[tokio::main]
async fn main() -> Result<()> {
    // Check for root privileges
    if !is_root() {
        eprintln!("Error: This program must be run as root (sudo).");
        eprintln!("Usage: sudo tunshare");
        std::process::exit(1);
    }

    // Set up panic hook to restore terminal on panic
    let original_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        // Restore terminal
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        original_hook(panic_info);
    }));

    // Run the app
    let result = run_app().await;

    // Restore terminal on exit
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;

    result
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

async fn run_app() -> Result<()> {
    // Setup terminal
    enable_raw_mode().context("Failed to enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("Failed to enter alternate screen")?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("Failed to create terminal")?;

    // Create app state
    let mut app = App::new();

    // Main loop using tokio for non-blocking event polling
    let mut interval = tokio::time::interval(Duration::from_millis(50));

    loop {
        // Poll for async operation results
        app.poll_async_results();

        // Draw UI
        terminal.draw(|frame| {
            let size = frame.area();

            // Calculate log panel height based on expansion state
            let log_height = if app.logs_expanded { 12 } else { 4 };

            // Main layout - new structure
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(1),          // Header (single line)
                    Constraint::Length(1),          // Separator
                    Constraint::Min(12),            // Main content
                    Constraint::Length(log_height), // Logs (collapsed/expanded)
                    Constraint::Length(1),          // Help
                ])
                .split(size);

            // Render header (single line)
            render_header(frame, chunks[0], &app);

            // Render separator
            render_separator(frame, chunks[1]);

            // Render main content based on state
            match app.state {
                AppState::Menu => {
                    if app.is_sharing() {
                        if !app.show_debug {
                            render_connection_info(frame, chunks[2], &app);
                        }
                    } else {
                        render_main_menu(frame, chunks[2], &app);
                    }
                }
                AppState::SelectingVpn => {
                    render_vpn_selection(frame, chunks[2], &app);
                }
                AppState::SelectingLan => {
                    render_lan_selection(frame, chunks[2], &app);
                }
                AppState::Active => {
                    if !app.show_debug {
                        render_connection_info(frame, chunks[2], &app);
                    }
                }
                AppState::EditingDns => {
                    render_main_menu(frame, chunks[2], &app);
                    render_dns_edit(frame, chunks[2], &app);
                }
            }

            // Render loading indicator if operation is pending
            if let Some(pending_op) = &app.pending_op {
                render_loading_indicator(
                    frame,
                    chunks[2],
                    pending_op.display(),
                    app.pending_elapsed(),
                );
            }

            // Render debug panel overlay if enabled
            if app.show_debug {
                if let Some(debug_info) = &app.debug_info {
                    render_debug_panel(frame, chunks[2], debug_info);
                }
            }

            // Render logs (with expansion state)
            let log_lines = chunks[3].height.saturating_sub(1) as usize;
            render_status_panel(frame, chunks[3], &app.logs, log_lines, app.logs_expanded);

            // Render help
            render_help(frame, chunks[4], app.help_text());
        })?;

        // Handle events with non-blocking poll
        tokio::select! {
            _ = interval.tick() => {
                // Check for crossterm events
                if event::poll(Duration::from_millis(0))? {
                    if let Event::Key(key) = event::read()? {
                        // Only handle key press events (not release)
                        if key.kind == KeyEventKind::Press {
                            // Global quit on Ctrl+C
                            if key.code == KeyCode::Char('c')
                                && key.modifiers.contains(event::KeyModifiers::CONTROL)
                            {
                                break;
                            }

                            app.handle_key(key.code);

                            if app.should_quit && app.pending_op.is_none() {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
