# AGENTS.md

Project-level guidance for AI agents working in this repository.

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
```

Release builds are produced by CI for distribution. For ad-hoc optimized testing, run `cargo build --release` directly.

## Architecture

### Module Structure

- **`src/main.rs`** - Entry point, terminal setup, main event loop using tokio/crossterm
- **`src/app.rs`** - Application state machine (Elm-style architecture) with async operation handling via mpsc channels
- **`src/error.rs`** - Error types using thiserror

**`src/system/`** - macOS system interactions:
- `firewall.rs` - pf firewall NAT rules, DNS `rdr`, optional WAN bypass table
- `sysctl.rs` - IP forwarding via sysctl
- `network.rs` - Interface detection (VPN vs LAN vs WAN uplink)
- `dns.rs` - DNS server discovery
- `dhcp.rs` - dnsmasq DHCP server management (DHCP only; DNS is in-process)
- `natpmp.rs` - Native NAT-PMP server (RFC 6886) for automatic port mapping, replaces external miniupnpd
- `lists.rs` - block/allow list fetch, cache, suffix match
- `resolver.rs` - LAN `:53` DNS server (hickory)

**`src/ui/`** - TUI components using ratatui:
- `main_menu.rs` - Main menu and connection info
- `interface_select.rs` - VPN/LAN interface selection
- `lists.rs` - Domain filters screen (Block / WAN bypass, per-source)
- `status.rs` - Log panel and loading indicators
- `debug.rs` - Debug overlay panel
- `theme.rs` - Color scheme
- `widgets/` - Reusable UI components (`card.rs` - Card widget)

### Key Patterns

- **Async operations**: System calls run in tokio tasks, results sent via `mpsc::UnboundedChannel<AsyncOpResult>` and polled in main loop
- **State machine**: `AppState` enum (Menu → SelectingVpn → SelectingLan → Active, plus EditingDns / ViewingLists)
- **Cleanup on drop**: `App::drop()` ensures resolver, NAT-PMP, firewall, and DHCP cleanup even on panic (resolver first so `:53` is free; NAT-PMP next so pf restore works)

## Requirements

- macOS (uses pf firewall and macOS-specific sysctl)
- Must run as root (sudo)
- Optional: `dnsmasq` for DHCP (`brew install dnsmasq`)


## Issue tracking — beads (bd)

This project uses [beads](https://github.com/steveyegge/beads) for all task tracking.

### Rules
- `bd` is the source of truth for all work — never use markdown TODO lists, and never use TodoWrite/TaskCreate to *track* work that should live in `bd`.
- File a `bd` issue **before** writing code; claim it (`bd update <id> --claim`) when you start.
- Once a bead is claimed, use `TodoWrite` to break it into in-session sub-tasks (or load the breakdown from the bead's `--design`/`--notes` if it's already there). TodoWrite is for the *execution slice* of one bead; `bd` is for everything that outlives the session.
- Before saying "done" at end of a session, close every completed issue: `bd close <id1> <id2> …`.
- `.beads/issues.jsonl` is committable — include it in commits without asking.

### Commands

**Finding work**
- `bd ready` — issues ready to work (no blockers)
- `bd list --status=open` / `--status=in_progress`
- `bd show <id>` — full issue with dependencies

**Creating & updating**
- `bd create --title="…" --description="…" --type=task|bug|feature|epic|chore --priority=2`
  - Priority is `0`–`4` (0=critical, 2=medium, 4=backlog). Not "high"/"low".
- `bd update <id> --claim` — atomic claim
- `bd update <id> --title/--description/--notes/--design "…"` — edit fields inline
- `bd close <id1> <id2> …` — close one or many; add `--reason="…"` if useful
- ⚠ Never use `bd edit` — it opens `$EDITOR` and blocks the agent.

`bd` also handles dependencies (`bd dep add`, `bd blocked`), deferring work (`bd defer`), and superseding issues (`bd supersede`). Run `bd --help` or `bd <command> --help` for syntax.
