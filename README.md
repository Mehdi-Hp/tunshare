<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./assets/logo-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="./assets/logo-light.png">
    <img src="./assets/logo-light.png" alt="tunshare logo" width="200">
  </picture>
</p>



# tunshare

A macOS TUI application that shares your VPN connection over LAN. Point other devices at your Mac and they get VPN-tunneled internet without needing their own VPN client.

## Why

macOS has built-in Internet Sharing, but it doesn't show most VPN interfaces. If your VPN creates a `utun` tunnel, it simply won't appear in the sharing dropdown -- there's no workaround in System Settings.

tunshare exists because of that gap. It detects your VPN tunnel directly, sets up NAT through macOS's `pf` firewall, and shares the connection over your LAN. Any device on your network -- smart TVs, game consoles, IoT gadgets, anything -- gets VPN-tunneled internet without needing its own VPN client.

## Features

- **NAT via pf** -- uses macOS's built-in packet filter, no third-party kernel extensions
- **Auto-detection** -- discovers VPN and LAN interfaces automatically (with manual override)
- **DHCP server** -- optionally runs `dnsmasq` so connected devices get IP addresses without manual config
- **NAT-PMP** -- native RFC 6886 server for automatic port mapping (replaces external miniupnpd)
- **DNS capture** -- LAN DNS is always this Mac (DHCP option 6 + pf `rdr` of port 53). Presets pick the VPN-path resolver behind that.
- **Domain filters** -- two-column TUI: Block (NXDOMAIN) and WAN bypass (split-tunnel). Each column has a master switch plus per-source on/off; add custom URLs in the TUI. Builtins stay, disable-only. Extra lists (HaGeZi Light/TIF, 1Hosts Lite, Phishing Army, China WAN) default off so enabling Block does not fetch megabytes. WAN bypass needs a WAN uplink besides LAN/VPN.
- **Health monitoring** -- detects VPN disconnects and IP forwarding changes within seconds, shown in the header
- **Persistent preferences** -- DHCP, NAT-PMP, DNS, and domain-filter toggles are saved across sessions
- **Debug panel** -- live view of active firewall rules, interface state, and NAT-PMP mappings
- **Clean shutdown** -- all firewall rules, IP forwarding, DHCP, and NAT-PMP are torn down on exit (even on panic)

## Requirements

- **macOS 11 (Big Sur) or later** (uses `pf` firewall and macOS-specific `sysctl`)
- **Root privileges** (`sudo`)
- **A wired LAN interface** (built-in ethernet, USB-ethernet, Thunderbolt-ethernet). See [Wired only](#wired-only) below.
- **Rust 1.85+** (if building from source)
- **Optional:** `dnsmasq` for DHCP (`brew install dnsmasq`)
- **Optional:** `just` for task runner commands (`brew install just`)

### Wired only

tunshare shares VPN traffic over a **wired** network interface. Wi-Fi is excluded from the LAN picker because your Mac would be a Wi-Fi *client*, not an access point — installing NAT rules on `en0` when it's joined to someone else's SSID can't reach any other devices.

If you want **wireless** clients to receive VPN traffic, the supported pattern is a travel router (or any router that supports AP mode) plugged into your Mac's ethernet:


<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./assets/diagram-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="./assets/diagram-light.png">
  <img src="./assets/diagram-light.png" alt="Topology: VPN → Mac (tunshare) → router (AP mode) → Wi-Fi clients">
</picture>


The Mac runs tunshare against the ethernet interface; the router's WAN port plugs into that ethernet; clients join the router's SSID and get VPN-tunneled internet. macOS's own Internet Sharing (which *can* drive a Wi-Fi AP) conflicts with tunshare's `pf` rules and is intentionally not used.

## Installation

### Homebrew

```bash
brew tap kumamaki/tap
brew install tunshare
```

### Build from source

```bash
git clone https://github.com/kumamaki/tunshare.git
cd tunshare
cargo build --release
```

The binary is at `./target/release/tunshare`.

## Usage

```bash
sudo tunshare
```

### Status (no TUI)

Inspect a running (or leftover) session from another terminal. Same binary, no checkout required.

```bash
sudo tunshare status
sudo tunshare status --check digikala.com
```

`--doctor` is preflight (can I start). `status` is live: process + pf NAT/rdr + WAN bypass table + list cache. `--check NAME` classifies NAME against cached lists, queries the LAN resolver, and for WAN-bypass names expects the A records in `<tunshare_bypass>`.

Exit `0` when the snapshot is consistent (sharing on and pf matches, or TUI down with no leftover NAT). `1` on leftover rules, TUI-without-sharing, or a name on neither list. `2` when the name is listed but the probe failed.

### Keyboard shortcuts

| Key | Action |
|-----|--------|
| `Up` / `k` | Navigate up |
| `Down` / `j` | Navigate down |
| `Enter` | Select / confirm |
| `Esc` | Cancel / go back |
| `s` | Stop sharing (when active) |
| `d` | Toggle debug panel (when active) |
| `l` | Domain filters (while sharing) / expand logs (idle menu) |
| `x` | Remove a custom source on Domain filters (builtins stay) |
| `Tab` / `←` `→` | Switch Domain filters column |
| `r` | Refresh Domain filters (on that screen) |
| `q` | Quit |
| `Ctrl+C` | Force quit |

### Workflow

1. Launch with `sudo tunshare`
2. Select **Start VPN Sharing** from the menu
3. Pick your VPN interface (or let it auto-detect)
4. Pick your LAN interface
5. Optionally configure DNS (the LAN resolver on this Mac; presets choose the VPN-path upstream)
6. Optionally open **Domain filters** to turn on Block or WAN bypass, toggle sources, or add URLs
7. Traffic from LAN devices now routes through your VPN (WAN-bypass domains go out WAN)
8. Press `s` to stop, `q` to quit

## How it works

1. **IP forwarding** -- enables `net.inet.ip.forwarding` via `sysctl`
2. **pf NAT rules** -- masquerades LAN traffic behind the VPN; always redirects LAN `:53` to this Mac. With WAN bypass on, destinations in `<tunshare_bypass>` NAT/`route-to` the WAN uplink
3. **DHCP** -- if `dnsmasq` is installed, runs it on the LAN interface (DHCP only, `port=0`) and advertises this Mac as DNS
4. **LAN resolver** -- in-process DNS on LAN `:53`. Blocked names → NXDOMAIN. WAN-bypass names resolve via WAN DNS, then join the pf bypass table before the answer
5. **NAT-PMP** -- runs a native NAT-PMP server (RFC 6886) on the LAN interface for automatic port mapping
6. **Cleanup** -- on exit (normal, error, or panic), the resolver, firewall, IP forwarding, DHCP, and NAT-PMP are torn down

## Development

Requires [just](https://github.com/casey/just) for task running.

```bash
just check       # Full check: format, lint, test, build
just dev         # Run in development mode (debug build)
just build       # Build debug version
just lint        # Run clippy
just test        # Run tests
just fmt         # Format code
just run-release # Build release and run with sudo
```

## License

[MIT](LICENSE)
