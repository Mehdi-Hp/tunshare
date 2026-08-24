//! Network interface detection for VPN and LAN interfaces.

use crate::error::{Result, TunshareError};
use crate::system::run_cmd;
use std::collections::HashMap;
use std::net::Ipv4Addr;

/// Information about a network interface.
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub ipv4_address: Option<Ipv4Addr>,
    pub ipv4_netmask: Option<Ipv4Addr>,
    pub description: Option<String>,
    pub is_up: bool,
}

impl InterfaceInfo {
    /// Network address for this interface's IPv4 + netmask, if both are
    /// present. Returns None for point-to-point /32 interfaces (no real
    /// subnet) and for interfaces without an address.
    pub fn ipv4_network(&self) -> Option<Ipv4Addr> {
        let ip = self.ipv4_address?;
        let mask = self.ipv4_netmask?;
        // /32 has no meaningful subnet — VPN point-to-point links land here.
        if u32::from(mask) == u32::MAX {
            return None;
        }
        Some(Ipv4Addr::from(u32::from(ip) & u32::from(mask)))
    }
}

/// True if two interfaces have addresses on the same IPv4 subnet (same
/// netmask AND same network address). Returns false if either lacks a
/// computable network (no address or /32 point-to-point).
pub fn same_ipv4_network(a: &InterfaceInfo, b: &InterfaceInfo) -> bool {
    match (
        a.ipv4_network(),
        b.ipv4_network(),
        a.ipv4_netmask,
        b.ipv4_netmask,
    ) {
        (Some(na), Some(nb), Some(ma), Some(mb)) => na == nb && ma == mb,
        _ => false,
    }
}

/// Read the interface name from `route -n get default` (IPv4 default route).
///
/// Returns `Ok(Some(name))` for the iface carrying the default route (a
/// `utun*` while a VPN is up, an `en*` when it's not), `Ok(None)` when no
/// default route exists, and an `Err` only when the command itself fails
/// to execute. Parse failures collapse to `Ok(None)` — better to treat an
/// unrecognized table as "no default route" than to bubble an error up
/// into the health probe.
pub async fn default_route_interface() -> Result<Option<String>> {
    let output = run_cmd("route", &["-n", "get", "default"]).await?;
    if !output.status.success() {
        // No default route → route(8) exits non-zero. Not an error.
        return Ok(None);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_default_route_interface(&stdout))
}

/// Extract the iface name from a `route -n get default` block. The relevant
/// line looks like `  interface: utun10`.
fn parse_default_route_interface(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("interface:") {
            let name = rest.trim();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    None
}

/// Detect VPN interfaces (utun* with IPv4 and point-to-point flag).
pub async fn detect_vpn_interfaces() -> Result<Vec<InterfaceInfo>> {
    let output = run_cmd("ifconfig", &["-a"]).await?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let interfaces = parse_interfaces(&stdout);

    let vpn_interfaces: Vec<InterfaceInfo> = interfaces
        .into_iter()
        .filter(|iface| {
            // VPN interfaces are typically utun* and have POINTOPOINT flag
            iface.name.starts_with("utun") && iface.is_up && iface.ipv4_address.is_some()
        })
        .collect();

    Ok(vpn_interfaces)
}

/// Detect LAN interfaces using networksetup to get hardware ports.
///
/// Wi-Fi interfaces are excluded even though they appear as `en*`: the Mac
/// is a Wi-Fi client, not an AP, so installing NAT rules on it doesn't
/// reach any clients. tunshare is wired-only by design — see README.
pub async fn detect_lan_interfaces() -> Result<Vec<InterfaceInfo>> {
    let ports_output = run_cmd("networksetup", &["-listallhardwareports"]).await?;
    let ports_stdout = String::from_utf8_lossy(&ports_output.stdout);
    let port_map = parse_hardware_ports(&ports_stdout);

    let ifconfig_output = run_cmd("ifconfig", &["-a"]).await?;
    let ifconfig_stdout = String::from_utf8_lossy(&ifconfig_output.stdout);
    let mut interfaces = parse_interfaces(&ifconfig_stdout);

    let lan_interfaces: Vec<InterfaceInfo> = interfaces
        .iter_mut()
        .filter(|iface| iface.name.starts_with("en") && iface.is_up && iface.ipv4_address.is_some())
        .map(|iface| {
            if let Some(desc) = port_map.get(&iface.name) {
                iface.description = Some(desc.clone());
            }
            iface.clone()
        })
        .filter(|iface| !is_wifi_port(iface.description.as_deref()))
        .collect();

    Ok(lan_interfaces)
}

/// True if the hardware-port description names a wireless interface.
/// macOS uses "Wi-Fi" on modern releases and "AirPort" on older ones.
fn is_wifi_port(description: Option<&str>) -> bool {
    match description {
        Some(d) => {
            let d = d.to_ascii_lowercase();
            d.contains("wi-fi") || d.contains("airport")
        }
        None => false,
    }
}

/// WAN uplink used to send allowlisted traffic around the VPN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WanUplink {
    pub iface: String,
    pub ip: Ipv4Addr,
    pub gateway: Ipv4Addr,
}

/// Outcome of WAN detection, including hairpins we refused.
///
/// `uplink` is the first remaining default from the IPv4 routing table after
/// skipping tunnel, share, and share-hairpin MACs. Empty ARP is fail-closed
/// on a missing ARP table, not a silent first leftover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WanDetect {
    pub uplink: Option<WanUplink>,
    pub skipped_hairpins: Vec<String>,
    pub arp_unavailable: bool,
}

impl WanDetect {
    pub fn format_found(&self) -> Option<String> {
        let wan = self.uplink.as_ref()?;
        let mut message = format!("WAN uplink <{}> via <{}>", wan.iface, wan.gateway);
        if !self.skipped_hairpins.is_empty() {
            message.push_str(" (skipped hairpin ");
            message.push_str(&self.skipped_hairpins.join(", "));
            message.push(')');
        }
        Some(message)
    }

    pub fn miss_message(&self) -> String {
        if self.arp_unavailable {
            "could not read ARP neighbors; refused a WAN pick that might hairpin the share LAN"
                .into()
        } else if !self.skipped_hairpins.is_empty() {
            format!(
                "every remaining ifscoped default hairpins the share LAN ({})",
                self.skipped_hairpins.join(", ")
            )
        } else {
            "need an ifscoped default besides LAN/VPN".into()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ArpSnapshot {
    Neighbors(Vec<ArpNeighbor>),
    Unavailable,
}

/// Find an ifscoped default that isn't the share LAN and isn't the VPN.
///
/// Hiddify analogue: OS default NIC, minus tunnel, minus share, minus a
/// gateway whose MAC is already a neighbor on the share iface (LAN vs WAN
/// of the same router). Wi-Fi is not preferred — on a dual-homed share box it is often
/// a LAN client of the router being fed. Travel-router Wi-Fi still wins when
/// it *is* the OS default and its AP MAC is not on the share cable.
pub async fn detect_wan_uplink(share_iface: &str, exclude: &[String]) -> Result<WanDetect> {
    let ifconfig_output = run_cmd("ifconfig", &["-a"]).await?;
    let ifconfig_stdout = String::from_utf8_lossy(&ifconfig_output.stdout);
    let interfaces = parse_interfaces(&ifconfig_stdout);

    let arp = match run_cmd("arp", &["-an"]).await {
        Ok(output) if output.status.success() => {
            ArpSnapshot::Neighbors(parse_arp_an(&String::from_utf8_lossy(&output.stdout)))
        }
        _ => ArpSnapshot::Unavailable,
    };
    let ranked_ifaces = match run_cmd("netstat", &["-rn", "-f", "inet"]).await {
        Ok(output) if output.status.success() => {
            parse_netstat_default_ifaces(&String::from_utf8_lossy(&output.stdout))
        }
        _ => Vec::new(),
    };

    let mut probed: HashMap<String, WanUplink> = HashMap::new();
    let mut probe_order = Vec::new();
    for iface in &interfaces {
        if !iface.is_up || iface.ipv4_address.is_none() {
            continue;
        }
        if iface.name.starts_with("lo") || iface.name.starts_with("utun") {
            continue;
        }
        if iface.name == share_iface || exclude.iter().any(|name| name == &iface.name) {
            continue;
        }
        let Some(uplink) = probe_ifscope_default(&iface.name, iface.ipv4_address).await? else {
            continue;
        };
        probe_order.push(iface.name.clone());
        probed.insert(iface.name.clone(), uplink);
    }

    let mut candidates = Vec::new();
    for name in ranked_ifaces {
        if let Some(uplink) = probed.remove(&name) {
            candidates.push(uplink);
        }
    }
    for name in probe_order {
        if let Some(uplink) = probed.remove(&name) {
            candidates.push(uplink);
        }
    }

    Ok(select_wan_uplink(candidates, share_iface, &arp))
}

fn parse_netstat_default_ifaces(output: &str) -> Vec<String> {
    let mut ifaces = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Internet6") {
            break;
        }
        let mut parts = trimmed.split_whitespace();
        let Some("default") = parts.next() else {
            continue;
        };
        // Darwin prints either `Gateway Flags Netif` or `Gateway Flags Refs Use Netif`.
        let Some(netif) = parts.rfind(|token| looks_like_netif(token)) else {
            continue;
        };
        if !ifaces.iter().any(|name| name == netif) {
            ifaces.push(netif.to_string());
        }
    }
    ifaces
}

fn looks_like_netif(token: &str) -> bool {
    let mut letters = false;
    let mut digits = false;
    for byte in token.bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' => letters = true,
            b'0'..=b'9' => digits = true,
            b'-' | b'_' => {}
            _ => return false,
        }
    }
    letters && digits
}

fn select_wan_uplink(
    candidates: Vec<WanUplink>,
    share_iface: &str,
    arp: &ArpSnapshot,
) -> WanDetect {
    let mut skipped_hairpins = Vec::new();
    let mut remaining = Vec::new();
    for uplink in candidates {
        if gateway_hairpins_share(uplink.gateway, share_iface, arp) {
            skipped_hairpins.push(uplink.iface);
        } else {
            remaining.push(uplink);
        }
    }

    if matches!(arp, ArpSnapshot::Unavailable) {
        return WanDetect {
            uplink: None,
            skipped_hairpins,
            arp_unavailable: true,
        };
    }

    WanDetect {
        uplink: remaining.into_iter().next(),
        skipped_hairpins,
        arp_unavailable: false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ArpNeighbor {
    ip: Ipv4Addr,
    mac: String,
    iface: String,
}

/// True when `gateway`'s MAC already appears as a neighbor on `share_iface`.
/// A missing ARP *entry* is not a hairpin (travel-router WAN is not on the
/// share cable). A missing ARP *table* is a hairpin — fail closed.
fn gateway_hairpins_share(gateway: Ipv4Addr, share_iface: &str, arp: &ArpSnapshot) -> bool {
    let neighbors = match arp {
        ArpSnapshot::Unavailable => return true,
        ArpSnapshot::Neighbors(neighbors) => neighbors,
    };
    let Some(mac) = neighbors
        .iter()
        .find(|neighbor| neighbor.ip == gateway)
        .map(|neighbor| neighbor.mac.as_str())
    else {
        return false;
    };
    neighbors
        .iter()
        .any(|neighbor| neighbor.iface == share_iface && neighbor.mac == mac)
}

fn parse_arp_an(output: &str) -> Vec<ArpNeighbor> {
    output.lines().filter_map(parse_arp_line).collect()
}

fn parse_arp_line(line: &str) -> Option<ArpNeighbor> {
    let ip_open = line.find('(')?;
    let after_open = &line[ip_open + 1..];
    let ip_close = after_open.find(')')?;
    let ip_token = &after_open[..ip_close];
    let ip: Ipv4Addr = ip_token.parse().ok()?;
    let after_at = line.split_once(" at ")?.1;
    let mut rest = after_at.split_whitespace();
    let mac_raw = rest.next()?;
    if mac_raw == "(incomplete)" {
        return None;
    }
    let mac = normalize_mac(mac_raw)?;
    if rest.next() != Some("on") {
        return None;
    }
    let iface = rest.next()?.to_string();
    Some(ArpNeighbor { ip, mac, iface })
}

fn normalize_mac(raw: &str) -> Option<String> {
    let mut out = String::with_capacity(17);
    let mut octets = 0usize;
    for part in raw.split(':') {
        if octets == 6
            || part.is_empty()
            || part.len() > 2
            || !part.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return None;
        }
        if octets > 0 {
            out.push(':');
        }
        if part.len() == 1 {
            out.push('0');
        }
        out.push_str(&part.to_ascii_lowercase());
        octets += 1;
    }
    (octets == 6).then_some(out)
}

async fn probe_ifscope_default(iface: &str, ip: Option<Ipv4Addr>) -> Result<Option<WanUplink>> {
    let ip = match ip {
        Some(ip) => ip,
        None => return Ok(None),
    };
    let output = run_cmd("route", &["-n", "get", "-ifscope", iface, "default"]).await?;
    if !output.status.success() {
        return Ok(None);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let Some(gateway) = parse_route_gateway(&stdout) else {
        return Ok(None);
    };
    Ok(Some(WanUplink {
        iface: iface.to_string(),
        ip,
        gateway,
    }))
}

/// Extract the gateway from a `route -n get` block. The line looks like
/// `    gateway: 192.168.1.1`.
fn parse_route_gateway(output: &str) -> Option<Ipv4Addr> {
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("gateway:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// Read the MTU of `iface` by parsing `ifconfig <iface>` output.
///
/// The header line of `ifconfig <iface>` always carries `mtu <N>` as its
/// trailing token on macOS, e.g. `en0: flags=...<UP,...> mtu 1500`.
pub async fn read_mtu(iface: &str) -> Result<u16> {
    let output = run_cmd("ifconfig", &[iface]).await?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_mtu(&stdout)
        .ok_or_else(|| TunshareError::ParseError(format!("no MTU line for interface <{iface}>")))
}

/// Extract the MTU from the first interface header line in ifconfig output.
fn parse_mtu(output: &str) -> Option<u16> {
    for line in output.lines() {
        if line.starts_with('\t') || line.starts_with(' ') {
            continue;
        }
        let mut tokens = line.split_whitespace();
        while let Some(tok) = tokens.next() {
            if tok == "mtu" {
                return tokens.next().and_then(|n| n.parse::<u16>().ok());
            }
        }
    }
    None
}

/// Parse an ifconfig hex netmask like `0xffffff00` into an `Ipv4Addr`.
fn parse_hex_netmask(s: &str) -> Option<Ipv4Addr> {
    let hex = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;
    let bits = u32::from_str_radix(hex, 16).ok()?;
    Some(Ipv4Addr::from(bits))
}

/// Parse ifconfig output to extract interface information.
fn parse_interfaces(output: &str) -> Vec<InterfaceInfo> {
    let mut interfaces = Vec::new();
    let mut current_iface: Option<InterfaceInfo> = None;

    for line in output.lines() {
        // New interface starts at column 0 (no leading whitespace)
        if !line.starts_with('\t') && !line.starts_with(' ') && line.contains(':') {
            // Save previous interface
            if let Some(iface) = current_iface.take() {
                interfaces.push(iface);
            }

            // Parse interface name (everything before first colon)
            if let Some(name_end) = line.find(':') {
                let name = line[..name_end].to_string();
                let is_up = line.contains("<UP");

                current_iface = Some(InterfaceInfo {
                    name,
                    ipv4_address: None,
                    ipv4_netmask: None,
                    description: None,
                    is_up,
                });
            }
        } else if let Some(ref mut iface) = current_iface {
            // Parse inet line for IPv4 address
            let trimmed = line.trim();
            if trimmed.starts_with("inet ") {
                // Format: inet 10.8.0.6 --> 10.8.0.5 netmask 0xffffffff
                // or:     inet 192.168.2.1 netmask 0xffffff00 broadcast 192.168.2.255
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    iface.ipv4_address = parts[1].parse::<Ipv4Addr>().ok();
                }
                if let Some(mask_idx) = parts.iter().position(|p| *p == "netmask") {
                    if let Some(mask_str) = parts.get(mask_idx + 1) {
                        iface.ipv4_netmask = parse_hex_netmask(mask_str);
                    }
                }
            }
        }
    }

    // Don't forget the last interface
    if let Some(iface) = current_iface {
        interfaces.push(iface);
    }

    interfaces
}

/// Parse networksetup -listallhardwareports output.
/// Returns a map of device name -> hardware port name.
fn parse_hardware_ports(output: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let mut current_port: Option<String> = None;

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Hardware Port:") {
            current_port = Some(
                trimmed
                    .trim_start_matches("Hardware Port:")
                    .trim()
                    .to_string(),
            );
        } else if trimmed.starts_with("Device:") {
            if let Some(port) = current_port.take() {
                let device = trimmed.trim_start_matches("Device:").trim().to_string();
                map.insert(device, port);
            }
        }
    }

    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_default_route_extracts_interface() {
        let output = "   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: utun10
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>";
        assert_eq!(
            parse_default_route_interface(output),
            Some("utun10".to_string())
        );
    }

    #[test]
    fn parse_default_route_returns_none_when_missing() {
        let output = "route to: default\nflags: <UP,GATEWAY>";
        assert_eq!(parse_default_route_interface(output), None);
    }

    #[test]
    fn parse_route_gateway_extracts_ipv4() {
        let output = "   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0";
        assert_eq!(
            parse_route_gateway(output),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
    }

    #[test]
    fn parse_route_gateway_skips_link_local_text() {
        // link#N is not an IPv4 next hop we can feed to pf route-to.
        assert_eq!(parse_route_gateway("    gateway: link#8"), None);
    }

    #[test]
    fn test_parse_interfaces() {
        let output = r#"lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
	options=1203<RXCSUM,TXCSUM,TXSTATUS,SW_TIMESTAMP>
	inet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	ether 00:11:22:33:44:55
	inet 192.168.2.1 netmask 0xffffff00 broadcast 192.168.2.255
utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500
	inet 10.8.0.6 --> 10.8.0.5 netmask 0xffffffff
"#;

        let interfaces = parse_interfaces(output);
        assert_eq!(interfaces.len(), 3);

        let en0 = interfaces.iter().find(|i| i.name == "en0").unwrap();
        assert!(en0.is_up);
        assert_eq!(en0.ipv4_address, Some(Ipv4Addr::new(192, 168, 2, 1)));
        assert_eq!(en0.ipv4_netmask, Some(Ipv4Addr::new(255, 255, 255, 0)));
        assert_eq!(en0.ipv4_network(), Some(Ipv4Addr::new(192, 168, 2, 0)));

        let utun3 = interfaces.iter().find(|i| i.name == "utun3").unwrap();
        assert!(utun3.is_up);
        assert_eq!(utun3.ipv4_address, Some(Ipv4Addr::new(10, 8, 0, 6)));
        assert_eq!(utun3.ipv4_netmask, Some(Ipv4Addr::new(255, 255, 255, 255)));
        // /32 P2P has no meaningful subnet
        assert_eq!(utun3.ipv4_network(), None);
    }

    fn iface(name: &str, ip: [u8; 4], mask: [u8; 4]) -> InterfaceInfo {
        InterfaceInfo {
            name: name.into(),
            ipv4_address: Some(Ipv4Addr::from(ip)),
            ipv4_netmask: Some(Ipv4Addr::from(mask)),
            description: None,
            is_up: true,
        }
    }

    #[test]
    fn same_subnet_detects_collision() {
        let a = iface("en0", [192, 168, 1, 10], [255, 255, 255, 0]);
        let b = iface("en1", [192, 168, 1, 20], [255, 255, 255, 0]);
        assert!(same_ipv4_network(&a, &b));
    }

    #[test]
    fn same_subnet_distinct_networks() {
        let a = iface("en0", [192, 168, 1, 10], [255, 255, 255, 0]);
        let b = iface("en1", [192, 168, 2, 10], [255, 255, 255, 0]);
        assert!(!same_ipv4_network(&a, &b));
    }

    #[test]
    fn parse_mtu_reads_header_line() {
        let output = "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tether 00:11:22:33:44:55\n\tinet 192.168.2.1 netmask 0xffffff00 broadcast 192.168.2.255\n";
        assert_eq!(parse_mtu(output), Some(1500));

        let utun = "utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1400\n\tinet 10.8.0.6 --> 10.8.0.5 netmask 0xffffffff\n";
        assert_eq!(parse_mtu(utun), Some(1400));

        assert_eq!(parse_mtu("no interface here\n"), None);
    }

    #[test]
    fn same_subnet_ignores_p2p() {
        let lan = iface("en0", [10, 8, 0, 5], [255, 255, 255, 0]);
        let vpn = iface("utun3", [10, 8, 0, 6], [255, 255, 255, 255]);
        // Even with matching IP prefix, /32 has no subnet so no collision.
        assert!(!same_ipv4_network(&lan, &vpn));
    }

    const FIXTURE_ARP: &str = "\
? (192.0.2.1) at 00:00:5e:00:53:aa on en0 ifscope [ethernet]
? (192.168.2.1) at 00:00:5e:00:53:cc on en8 ifscope permanent [ethernet]
? (192.168.2.50) at 00:00:5e:00:53:bb on en8 ifscope [ethernet]
? (198.51.100.1) at 00:00:5e:00:53:bb on en1 ifscope [ethernet]
? (198.51.100.50) at (incomplete) on en4 ifscope [ethernet]
";

    fn fixture_arp() -> ArpSnapshot {
        ArpSnapshot::Neighbors(parse_arp_an(FIXTURE_ARP))
    }

    fn wan(iface: &str, ip: [u8; 4], gateway: [u8; 4]) -> WanUplink {
        WanUplink {
            iface: iface.into(),
            ip: Ipv4Addr::from(ip),
            gateway: Ipv4Addr::from(gateway),
        }
    }

    #[test]
    fn parse_arp_skips_incomplete_and_pads_octets() {
        let ArpSnapshot::Neighbors(neighbors) = fixture_arp() else {
            panic!("fixture ARP is neighbors");
        };
        let share = neighbors
            .iter()
            .find(|n| n.ip == Ipv4Addr::new(192, 168, 2, 1))
            .expect("share self");
        assert_eq!(share.mac, "00:00:5e:00:53:cc");
        assert_eq!(share.iface, "en8");
        let ips: Vec<_> = neighbors.iter().map(|n| n.ip).collect();
        assert_eq!(
            ips,
            vec![
                Ipv4Addr::new(192, 0, 2, 1),
                Ipv4Addr::new(192, 168, 2, 1),
                Ipv4Addr::new(192, 168, 2, 50),
                Ipv4Addr::new(198, 51, 100, 1),
            ]
        );
    }

    #[test]
    fn router_lan_gateway_hairpins_share() {
        let arp = fixture_arp();
        assert!(gateway_hairpins_share(
            Ipv4Addr::new(198, 51, 100, 1),
            "en8",
            &arp
        ));
        assert!(!gateway_hairpins_share(
            Ipv4Addr::new(192, 0, 2, 1),
            "en8",
            &arp
        ));
        assert!(!gateway_hairpins_share(
            Ipv4Addr::new(1, 1, 1, 1),
            "en8",
            &arp
        ));
        assert!(gateway_hairpins_share(
            Ipv4Addr::new(192, 0, 2, 1),
            "en8",
            &ArpSnapshot::Unavailable
        ));
    }

    #[test]
    fn parse_netstat_ranks_defaults_and_skips_v6() {
        let table = "\
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            10.8.0.5           UGScg               utun4
default            198.51.100.1       UGScIg               en1
default            192.0.2.1      UGScIg               en0
127                127.0.0.1          UCS                  lo0

Internet6:
Destination                             Gateway                                 Flags         Netif Expire
default                                 fe80::%utun4                            UGcI          utun4
";
        assert_eq!(
            parse_netstat_default_ifaces(table),
            vec!["utun4", "en1", "en0"]
        );

        let with_refs = "\
Destination        Gateway            Flags            Refs      Use Netif Expire
default            10.8.0.5           UGScg               6        0 utun4
default            192.0.2.1      UGScIg              1        0   en0
";
        assert_eq!(
            parse_netstat_default_ifaces(with_refs),
            vec!["utun4", "en0"]
        );
    }

    #[test]
    fn select_skips_hairpin_even_when_it_ranks_first() {
        let candidates = vec![
            wan("en1", [198, 51, 100, 50], [198, 51, 100, 1]),
            wan("en0", [192, 0, 2, 2], [192, 0, 2, 1]),
        ];
        let picked = select_wan_uplink(candidates, "en8", &fixture_arp());
        assert_eq!(
            picked.uplink.as_ref().map(|w| w.iface.as_str()),
            Some("en0")
        );
        assert_eq!(picked.skipped_hairpins, vec!["en1".to_string()]);
        assert!(!picked.arp_unavailable);
    }

    #[test]
    fn select_refuses_when_arp_is_unavailable() {
        let candidates = vec![wan("en0", [192, 0, 2, 2], [192, 0, 2, 1])];
        let picked = select_wan_uplink(candidates, "en8", &ArpSnapshot::Unavailable);
        assert!(picked.uplink.is_none());
        assert!(picked.arp_unavailable);
        assert_eq!(picked.skipped_hairpins, vec!["en0".to_string()]);
    }

    #[test]
    fn select_logs_skipped_hairpins_when_a_later_candidate_wins() {
        let candidates = vec![
            wan("en1", [198, 51, 100, 50], [198, 51, 100, 1]),
            wan("en0", [192, 0, 2, 2], [192, 0, 2, 1]),
        ];
        let picked = select_wan_uplink(candidates, "en8", &fixture_arp());
        assert_eq!(
            picked.format_found().as_deref(),
            Some("WAN uplink <en0> via <192.0.2.1> (skipped hairpin en1)")
        );
    }

    #[test]
    fn miss_message_names_hairpin_or_arp() {
        let hairpin_only = select_wan_uplink(
            vec![wan("en1", [198, 51, 100, 50], [198, 51, 100, 1])],
            "en8",
            &fixture_arp(),
        );
        assert!(hairpin_only.uplink.is_none());
        assert_eq!(
            hairpin_only.miss_message(),
            "every remaining ifscoped default hairpins the share LAN (en1)"
        );
        let arp_down = select_wan_uplink(
            vec![wan("en0", [192, 0, 2, 2], [192, 0, 2, 1])],
            "en8",
            &ArpSnapshot::Unavailable,
        );
        assert!(arp_down.miss_message().contains("could not read ARP"));
    }
}
