//! Network interface detection for VPN and LAN interfaces.

use crate::error::{Result, VpnShareError};
use tokio::process::Command;

/// Information about a network interface.
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub ipv4_address: Option<String>,
    pub description: Option<String>,
    pub is_up: bool,
}

/// Detect VPN interfaces (utun* with IPv4 and point-to-point flag).
pub async fn detect_vpn_interfaces() -> Result<Vec<InterfaceInfo>> {
    let output = Command::new("ifconfig")
        .arg("-a")
        .output()
        .await
        .map_err(|e| VpnShareError::CommandFailed {
            command: "ifconfig -a".into(),
            message: e.to_string(),
        })?;

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
    // Get hardware ports mapping
    let ports_output = Command::new("networksetup")
        .args(["-listallhardwareports"])
        .output()
        .await
        .map_err(|e| VpnShareError::CommandFailed {
            command: "networksetup -listallhardwareports".into(),
            message: e.to_string(),
        })?;

    let ports_stdout = String::from_utf8_lossy(&ports_output.stdout);
    let port_map = parse_hardware_ports(&ports_stdout);

    // Get interface details from ifconfig
    let ifconfig_output = Command::new("ifconfig")
        .arg("-a")
        .output()
        .await
        .map_err(|e| VpnShareError::CommandFailed {
            command: "ifconfig -a".into(),
            message: e.to_string(),
        })?;

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
                    iface.ipv4_address = Some(parts[1].to_string());
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
        assert_eq!(en0.ipv4_address, Some("192.168.2.1".to_string()));

        let utun3 = interfaces.iter().find(|i| i.name == "utun3").unwrap();
        assert!(utun3.is_up);
        assert_eq!(utun3.ipv4_address, Some("10.8.0.6".to_string()));
    }
}
