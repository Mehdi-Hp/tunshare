# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

tunshare is a Rust TUI application for macOS that routes internet traffic through a VPN and shares it via LAN. Uses macOS's `pf` (packet filter) firewall for NAT and optionally `dnsmasq` for DHCP.

## Commands

```bash
just build   # Build the debug binary
just run     # Build and run with sudo (always rebuilds — no stale-binary trap)
just lint    # Run clippy
just test    # Run tests
just fmt     # Format code
just check   # Full pre-commit: fmt-check, lint, test, build
just clean   # Clean build artifacts
just push-to-server # Builds and pushes the binary to home server
```

Release builds are produced by CI for distribution. For ad-hoc optimized testing, run `cargo build --release` directly.

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


<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:7510c1e2 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/SYNC_CONCEPTS.md for details and anti-patterns.

## Session Completion

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
<!-- END BEADS INTEGRATION -->
