# tunshare

A macOS TUI application that shares your VPN connection over LAN. Point other devices at your Mac and they get VPN-tunneled internet without needing their own VPN client.

## Why

Some devices -- smart TVs, game consoles, IoT gadgets -- either can't run a VPN client or make it painfully annoying. tunshare turns your Mac into a NAT gateway: it detects your VPN and LAN interfaces, configures macOS's `pf` firewall, and forwards traffic so any device on your local network can route through your VPN.

## Features

- **NAT via pf** -- uses macOS's built-in packet filter, no third-party kernel extensions
- **Auto-detection** -- discovers VPN and LAN interfaces automatically (with manual override)
- **DHCP server** -- optionally runs `dnsmasq` so connected devices get IP addresses without manual config
- **NAT-PMP** -- native RFC 6886 server for automatic port mapping (replaces external miniupnpd)
- **DNS configuration** -- choose from presets (Cloudflare, Google, Quad9) or enter a custom DNS server
- **Debug panel** -- live view of active firewall rules, interface state, and NAT-PMP mappings
- **Clean shutdown** -- all firewall rules, IP forwarding, DHCP, and NAT-PMP are torn down on exit (even on panic)

## Requirements

- **macOS** (uses `pf` firewall and macOS-specific `sysctl`)
- **Root privileges** (`sudo`)
- **Rust toolchain** (if building from source)
- **Optional:** `dnsmasq` for DHCP (`brew install dnsmasq`)
- **Optional:** `just` for task runner commands (`brew install just`)

## Installation

### Homebrew

```bash
brew tap Mehdi-Hp/tap
brew install tunshare
```

### Build from source

```bash
git clone https://github.com/Mehdi-Hp/tunshare.git
cd tunshare
cargo build --release
```

The binary is at `./target/release/tunshare`.

## Usage

```bash
sudo tunshare
```

### Keyboard shortcuts

| Key | Action |
|-----|--------|
| `Up` / `k` | Navigate up |
| `Down` / `j` | Navigate down |
| `Enter` | Select / confirm |
| `Esc` | Cancel / go back |
| `s` | Stop sharing (when active) |
| `d` | Toggle debug panel (when active) |
| `l` | Toggle log panel expansion |
| `q` | Quit |
| `Ctrl+C` | Force quit |

### Workflow

1. Launch with `sudo tunshare`
2. Select **Start VPN Sharing** from the menu
3. Pick your VPN interface (or let it auto-detect)
4. Pick your LAN interface
5. Optionally configure DNS (menu option 2)
6. Traffic from LAN devices now routes through your VPN
7. Press `s` to stop, `q` to quit

## How it works

1. **IP forwarding** -- enables `net.inet.ip.forwarding` via `sysctl`
2. **pf NAT rules** -- loads a NAT rule into a dedicated `vpn_share` anchor so LAN traffic is masqueraded behind the VPN interface
3. **DHCP** -- if `dnsmasq` is installed, runs it on the LAN interface so connected devices get an IP automatically
4. **NAT-PMP** -- runs a native NAT-PMP server (RFC 6886) on the LAN interface for automatic port mapping
5. **DNS** -- configures the DNS server used by connected devices (auto-detected or manually set)
6. **Cleanup** -- on exit (normal, error, or panic), all rules are flushed, IP forwarding is restored, DHCP and NAT-PMP servers are stopped

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
