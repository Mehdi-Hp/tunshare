# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

tunshare is a Rust TUI application for macOS that routes internet traffic through a VPN and shares it via LAN. Uses macOS's `pf` (packet filter) firewall for NAT and optionally `dnsmasq` for DHCP.

## Commands

```bash
# Development
just build          # Build debug version
just dev            # Run in development mode (debug)
just lint           # Run clippy
just test           # Run tests
just fmt            # Format code
just fmt-check      # Check formatting without modifying
just check          # Full check: fmt-check, lint, test, build
just clean          # Clean build artifacts

# Production (requires sudo)
just build-release  # Build optimized release
just run            # Run existing release binary with sudo
just run-release    # Build and run release with sudo
sudo ./target/release/tunshare  # Run directly
```

## Architecture

### Module Structure

- **`src/main.rs`** - Entry point, terminal setup, main event loop using tokio/crossterm
- **`src/app.rs`** - Application state machine (Elm-style architecture) with async operation handling via mpsc channels
- **`src/error.rs`** - Error types using thiserror

**`src/system/`** - macOS system interactions:
- `firewall.rs` - pf firewall NAT rules (load/cleanup)
- `sysctl.rs` - IP forwarding via sysctl
- `network.rs` - Interface detection (VPN vs LAN)
- `dns.rs` - DNS server discovery
- `dhcp.rs` - dnsmasq DHCP server management
- `natpmp.rs` - Native NAT-PMP server (RFC 6886) for automatic port mapping, replaces external miniupnpd

**`src/ui/`** - TUI components using ratatui:
- `main_menu.rs` - Main menu and connection info
- `interface_select.rs` - VPN/LAN interface selection
- `status.rs` - Log panel and loading indicators
- `debug.rs` - Debug overlay panel
- `theme.rs` - Color scheme
- `widgets/` - Reusable UI components (`card.rs` - Card widget)

### Key Patterns

- **Async operations**: System calls run in tokio tasks, results sent via `mpsc::UnboundedChannel<AsyncOpResult>` and polled in main loop
- **State machine**: `AppState` enum (Menu → SelectingVpn → SelectingLan → Active, plus EditingDns for custom DNS input)
- **Cleanup on drop**: `App::drop()` ensures NAT-PMP, firewall, and DHCP cleanup even on panic (NAT-PMP stops first so pf anchor flush works)

## Requirements

- macOS (uses pf firewall and macOS-specific sysctl)
- Must run as root (sudo)
- Optional: `dnsmasq` for DHCP (`brew install dnsmasq`)
