# Changelog

All notable changes to tunshare are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `--version` and `--help` flags.
- Homebrew distribution via `kumamaki/homebrew-tap`.
- App state-machine smoke tests.
- **VPN-drop auto-recovery.** When the VPN interface drops mid-session,
  tunshare now reacts according to a configurable `vpn_drop_strategy`:
  `WaitWithTimeout(15s)` (default), `AutoStop`, or `Ignore`. Header shows
  a live countdown while waiting.
- **DNS history.** The DNS picker remembers up to 10 recently-used
  custom DNS servers under the built-in presets; press `[x]` to remove
  one. Old single-slot `custom_dns` configs auto-populate history on
  first load.
- **Doctor.** New "Run Doctor" menu entry and `--doctor` CLI flag run
  12 diagnostic checks (privilege, required tools, dnsmasq, IP
  forwarding state, pf enabled, stale anchor, macOS Internet Sharing
  conflict, foreign dnsmasq, NAT-PMP port, VPN interface, LAN
  interface, config dir writable). In-app: `[c]` flushes a stale
  `vpn_share` pf anchor inline; `[r]` re-runs. CLI exits non-zero on
  any fail for scripting.

### Changed
- Internal `system::run_cmd` helper consolidates the shell-out + error
  conversion pattern previously repeated across every `system/` module.
- DNS picker code paths restructured to remove unwrap() calls.

### Removed
- Dead code: `App::is_loading`, `IpForwarding::disable`, `Firewall::is_loaded`,
  and unused `NoVpnInterfaces` / `NoLanInterfaces` error variants.

## [0.1.0] - 2025-11-08

### Added
- Initial public release.
- NAT via macOS `pf` firewall.
- VPN/LAN interface auto-detection with manual override.
- Optional DHCP server via `dnsmasq`.
- Native NAT-PMP server (RFC 6886) replacing external `miniupnpd`.
- DNS picker with Cloudflare/Google/Quad9 presets and custom override.
- Persistent preferences (`~/.config/tunshare/config.json`).
- Periodic VPN/IP-forwarding health monitoring shown in the header.
- Debug overlay with live pf rules, NAT-PMP mappings, interface state.
- Drop-safe cleanup of all firewall, IP forwarding, DHCP, and NAT-PMP state.

[Unreleased]: https://github.com/kumamaki/tunshare/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kumamaki/tunshare/releases/tag/v0.1.0
