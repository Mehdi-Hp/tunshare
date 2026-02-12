//! VPN DNS server discovery via scutil --dns.

use crate::error::{Result, VpnShareError};
use tokio::process::Command;

/// Discover DNS servers associated with a VPN interface.
///
/// Parses `scutil --dns` output to find resolver configurations
/// that are associated with the given VPN interface.
pub async fn discover_vpn_dns(vpn_interface: &str) -> Result<Vec<String>> {
    let output = Command::new("scutil")
        .arg("--dns")
        .output()
        .await
        .map_err(|e| VpnShareError::CommandFailed {
            command: "scutil --dns".into(),
            message: e.to_string(),
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let dns_servers = parse_dns_for_interface(&stdout, vpn_interface);

    Ok(dns_servers)
}

/// Parse scutil --dns output looking for DNS servers associated with interface.
fn parse_dns_for_interface(output: &str, interface: &str) -> Vec<String> {
    let mut dns_servers = Vec::new();
    let mut in_relevant_resolver = false;
    let mut current_nameservers: Vec<String> = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();

        // New resolver block
        if trimmed.starts_with("resolver #") {
            // Save previous if it was relevant
            if in_relevant_resolver {
                dns_servers.append(&mut current_nameservers);
            }
            in_relevant_resolver = false;
            current_nameservers.clear();
        }

        // Check if this resolver is for our interface
        // Look for "if_index : N (utun3)" pattern
        if trimmed.starts_with("if_index") && trimmed.contains(&format!("({})", interface)) {
            in_relevant_resolver = true;
        }

        // Also check for interface field directly
        if trimmed.starts_with("interface") && trimmed.contains(interface) {
            in_relevant_resolver = true;
        }

        // Collect nameservers
        if trimmed.starts_with("nameserver[") {
            // Format: "nameserver[0] : 10.8.0.1"
            if let Some(pos) = trimmed.find(" : ") {
                let server = trimmed[pos + 3..].trim().to_string();
                if !server.is_empty() {
                    current_nameservers.push(server);
                }
            }
        }
    }

    // Don't forget the last resolver block
    if in_relevant_resolver {
        dns_servers.extend(current_nameservers);
    }

    // Deduplicate
    dns_servers.sort();
    dns_servers.dedup();

    dns_servers
}

/// Get the default DNS servers (from system configuration).
pub async fn get_default_dns() -> Result<Vec<String>> {
    let output = Command::new("scutil")
        .arg("--dns")
        .output()
        .await
        .map_err(|e| VpnShareError::CommandFailed {
            command: "scutil --dns".into(),
            message: e.to_string(),
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let dns_servers = parse_default_dns(&stdout);

    Ok(dns_servers)
}

/// Parse default DNS from scutil output (looks for the primary resolver).
fn parse_default_dns(output: &str) -> Vec<String> {
    let mut dns_servers = Vec::new();
    let mut in_default_resolver = false;

    for line in output.lines() {
        let trimmed = line.trim();

        // Look for "DNS configuration (for scoped queries)" or the first resolver
        if trimmed.starts_with("resolver #1") {
            in_default_resolver = true;
        } else if trimmed.starts_with("resolver #") && in_default_resolver {
            // We've moved past the first resolver
            break;
        }

        if in_default_resolver && trimmed.starts_with("nameserver[") {
            if let Some(pos) = trimmed.find(" : ") {
                let server = trimmed[pos + 3..].trim().to_string();
                if !server.is_empty() {
                    dns_servers.push(server);
                }
            }
        }
    }

    dns_servers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns_for_interface() {
        let output = r#"
DNS configuration

resolver #1
  nameserver[0] : 192.168.1.1
  if_index : 5 (en0)
  flags    : Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

resolver #2
  nameserver[0] : 10.8.0.1
  if_index : 23 (utun3)
  flags    : Request A records
  reach    : 0x00000002 (Reachable)

resolver #3
  domain   : local
  options  : mdns
  timeout  : 5
  flags    : Request A records
"#;

        let dns = parse_dns_for_interface(output, "utun3");
        assert_eq!(dns, vec!["10.8.0.1"]);

        let dns_en0 = parse_dns_for_interface(output, "en0");
        assert_eq!(dns_en0, vec!["192.168.1.1"]);
    }
}
