//! Network interface detection for VPN and LAN interfaces.

use crate::error::Result;
use crate::system::run_cmd;
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
pub async fn detect_lan_interfaces() -> Result<Vec<InterfaceInfo>> {
    let ports_output = run_cmd("networksetup", &["-listallhardwareports"]).await?;
    let ports_stdout = String::from_utf8_lossy(&ports_output.stdout);
    let port_map = parse_hardware_ports(&ports_stdout);

    let ifconfig_output = run_cmd("ifconfig", &["-a"]).await?;
    let ifconfig_stdout = String::from_utf8_lossy(&ifconfig_output.stdout);
    let mut interfaces = parse_interfaces(&ifconfig_stdout);

    // Filter to LAN interfaces (en*) that are up with IPv4
    let lan_interfaces: Vec<InterfaceInfo> = interfaces
        .iter_mut()
        .filter(|iface| iface.name.starts_with("en") && iface.is_up && iface.ipv4_address.is_some())
        .map(|iface| {
            // Add description from hardware ports
            if let Some(desc) = port_map.get(&iface.name) {
                iface.description = Some(desc.clone());
            }
            iface.clone()
        })
        .collect();

    Ok(lan_interfaces)
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
    fn same_subnet_ignores_p2p() {
        let lan = iface("en0", [10, 8, 0, 5], [255, 255, 255, 0]);
        let vpn = iface("utun3", [10, 8, 0, 6], [255, 255, 255, 255]);
        // Even with matching IP prefix, /32 has no subnet so no collision.
        assert!(!same_ipv4_network(&lan, &vpn));
    }
}
