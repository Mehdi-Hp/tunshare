# Changelog

All notable changes to tunshare are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `--version` and `--help` flags.
- Homebrew distribution via `kumamaki/homebrew-tap`.
- App state-machine smoke tests.

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
