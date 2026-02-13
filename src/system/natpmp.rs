//! Native NAT-PMP server (RFC 6886) for automatic port mapping.
//!
//! Replaces the external miniupnpd dependency with a pure Rust implementation
//! that runs as a tokio task inside the existing async runtime.

use crate::error::{Result, TunshareError};
use std::collections::HashMap;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::process::Command as SyncCommand;
use std::time::Instant;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::process::Command;
use tokio::sync::watch;

const NATPMP_PORT: u16 = 5351;
/// RFC 6886: response opcode = request opcode + 128.
const RESPONSE_FLAG: u8 = 128;
const PF_ANCHOR_NAME: &str = "natpmp";
const MAX_LIFETIME: u32 = 7200;
const MIN_ALLOWED_PORT: u16 = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Protocol {
    Udp,
    Tcp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Udp => f.write_str("udp"),
            Protocol::Tcp => f.write_str("tcp"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MappingKey {
    protocol: Protocol,
    external_port: u16,
}

#[derive(Debug, Clone)]
struct Mapping {
    internal_ip: Ipv4Addr,
    internal_port: u16,
    external_port: u16,
    protocol: Protocol,
    lifetime_secs: u32,
    created_at: Instant,
}

impl Mapping {
    fn is_expired(&self) -> bool {
        self.created_at.elapsed().as_secs() >= self.lifetime_secs as u64
    }
}

/// NAT-PMP server that runs as a tokio task.
pub struct NatPmpServer {
    ext_ifname: String,
    lan_network: String,
    shutdown_tx: watch::Sender<bool>,
}

impl NatPmpServer {
    /// Create a new NAT-PMP server instance.
    ///
    /// `lan_ifname` is accepted for future use (e.g., binding the UDP socket to
    /// the LAN interface only) but is not currently used.
    pub fn new(ext_ifname: &str, _lan_ifname: &str, lan_network: &str) -> Self {
        let (shutdown_tx, _) = watch::channel(false);
        Self {
            ext_ifname: ext_ifname.to_string(),
            lan_network: lan_network.to_string(),
            shutdown_tx,
        }
    }

    /// Start the NAT-PMP server. Spawns a long-lived tokio task.
    pub async fn start(&self) -> Result<()> {
        // Flush any stale anchor rules from a previous run
        Self::stop().await.ok();

        let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, NATPMP_PORT);
        let socket = UdpSocket::bind(addr)
            .await
            .map_err(|e| TunshareError::CommandFailed {
                command: "bind NAT-PMP UDP socket".into(),
                message: format!("Failed to bind port {}: {}", NATPMP_PORT, e),
            })?;

        let ext_ifname = self.ext_ifname.clone();
        let lan_network = self.lan_network.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            let mut mappings: HashMap<MappingKey, Mapping> = HashMap::new();
            let mut buf = [0u8; 64];
            let mut external_ip = get_interface_ip(&ext_ifname)
                .await
                .unwrap_or(Ipv4Addr::UNSPECIFIED);
            let mut expiry_interval = tokio::time::interval(std::time::Duration::from_secs(30));
            let mut ip_refresh_interval = tokio::time::interval(std::time::Duration::from_secs(60));
            // Consume the first immediate ticks
            expiry_interval.tick().await;
            ip_refresh_interval.tick().await;

            let server_start = Instant::now();

            loop {
                tokio::select! {
                    result = socket.recv_from(&mut buf) => {
                        match result {
                            Ok((len, src)) => {
                                if !is_lan_client(&src, &lan_network) {
                                    continue;
                                }
                                if let Some(response) = handle_request(
                                    &buf[..len],
                                    src,
                                    external_ip,
                                    server_start,
                                    &ext_ifname,
                                    &mut mappings,
                                ).await {
                                    let _ = socket.send_to(&response, src).await;
                                }
                            }
                            Err(_) => continue,
                        }
                    }
                    _ = expiry_interval.tick() => {
                        let before = mappings.len();
                        mappings.retain(|_, m| !m.is_expired());
                        if mappings.len() != before {
                            reload_anchor_rules(&ext_ifname, &mappings).await;
                        }
                    }
                    _ = ip_refresh_interval.tick() => {
                        if let Some(ip) = get_interface_ip(&ext_ifname).await {
                            external_ip = ip;
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            flush_anchor_rules().await;
                            break;
                        }
                    }
                }
            }
        });

        Ok(())
    }

    /// Signal the server task to shut down.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// Flush all NAT-PMP pf anchor rules (async wrapper).
    /// Delegates to `stop_sync` via `spawn_blocking`.
    pub async fn stop() -> Result<()> {
        tokio::task::spawn_blocking(Self::stop_sync)
            .await
            .map_err(|e| TunshareError::CommandFailed {
                command: "natpmp stop (spawn_blocking)".into(),
                message: e.to_string(),
            })?;
        Ok(())
    }

    /// Synchronous flush. Single source of truth for NAT-PMP cleanup.
    pub fn stop_sync() {
        let _ = SyncCommand::new("pfctl")
            .args(["-a", PF_ANCHOR_NAME, "-F", "all"])
            .output();
    }

    /// Derive a /24 network CIDR from a gateway IP (e.g., 192.168.2.1 -> "192.168.2.0/24").
    pub fn network_from_ip(ip: Ipv4Addr) -> String {
        let o = ip.octets();
        format!("{}.{}.{}.0/24", o[0], o[1], o[2])
    }
}

/// Check if a client address is on the LAN network (CIDR /24 check).
fn is_lan_client(src: &SocketAddr, lan_network: &str) -> bool {
    let client_ip = match src {
        SocketAddr::V4(v4) => *v4.ip(),
        SocketAddr::V6(_) => return false,
    };

    let Some((network_str, prefix_str)) = lan_network.split_once('/') else {
        return false;
    };

    let Ok(network_ip) = network_str.parse::<Ipv4Addr>() else {
        return false;
    };
    let Ok(prefix_len) = prefix_str.parse::<u32>() else {
        return false;
    };

    if prefix_len > 32 {
        return false;
    }

    let mask = if prefix_len == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix_len)
    };

    let client_bits = u32::from(client_ip);
    let network_bits = u32::from(network_ip);

    (client_bits & mask) == (network_bits & mask)
}

/// Handle a single NAT-PMP request, returning the response bytes.
async fn handle_request(
    data: &[u8],
    src: SocketAddr,
    external_ip: Ipv4Addr,
    server_start: Instant,
    ext_ifname: &str,
    mappings: &mut HashMap<MappingKey, Mapping>,
) -> Option<Vec<u8>> {
    if data.len() < 2 {
        return None;
    }

    let version = data[0];
    if version != 0 {
        return Some(build_error_response(RESPONSE_FLAG, 1)); // Unsupported version
    }

    let opcode = data[1];
    let sssoe = server_start.elapsed().as_secs() as u32;

    match opcode {
        // Opcode 0: Get external address
        0 => Some(build_external_address_response(sssoe, external_ip)),
        // Opcode 1: Map UDP, Opcode 2: Map TCP
        1 | 2 => {
            let resp_opcode = RESPONSE_FLAG + opcode;
            if data.len() < 12 {
                return Some(build_error_response(resp_opcode, 2)); // Bad request
            }

            let protocol = if opcode == 1 {
                Protocol::Udp
            } else {
                Protocol::Tcp
            };

            let internal_port = u16::from_be_bytes([data[4], data[5]]);
            let suggested_external = u16::from_be_bytes([data[6], data[7]]);
            let lifetime = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

            let client_ip = match src {
                SocketAddr::V4(v4) => *v4.ip(),
                _ => return Some(build_error_response(resp_opcode, 2)),
            };

            // Delete all mappings for this client
            if lifetime == 0 && internal_port == 0 {
                let before = mappings.len();
                mappings.retain(|_, m| m.internal_ip != client_ip);
                if mappings.len() != before {
                    reload_anchor_rules(ext_ifname, mappings).await;
                }
                return Some(build_mapping_response(resp_opcode, sssoe, 0, 0, 0));
            }

            // Determine external port
            let external_port = if suggested_external >= MIN_ALLOWED_PORT {
                let key = MappingKey {
                    protocol,
                    external_port: suggested_external,
                };
                if !mappings.contains_key(&key)
                    || mappings.get(&key).map(|m| m.internal_ip) == Some(client_ip)
                {
                    suggested_external
                } else {
                    match find_available_port(mappings, protocol) {
                        Some(p) => p,
                        None => return Some(build_error_response(resp_opcode, 4)), // Out of resources
                    }
                }
            } else if lifetime == 0 {
                // Delete specific mapping: find it by internal port + client
                let to_remove: Vec<MappingKey> = mappings
                    .iter()
                    .filter(|(_, m)| {
                        m.internal_ip == client_ip
                            && m.internal_port == internal_port
                            && m.protocol == protocol
                    })
                    .map(|(k, _)| k.clone())
                    .collect();
                for key in &to_remove {
                    mappings.remove(key);
                }
                if !to_remove.is_empty() {
                    reload_anchor_rules(ext_ifname, mappings).await;
                }
                return Some(build_mapping_response(
                    resp_opcode,
                    sssoe,
                    internal_port,
                    0,
                    0,
                ));
            } else {
                // Suggested port < 1024, find a free one
                match find_available_port(mappings, protocol) {
                    Some(p) => p,
                    None => return Some(build_error_response(resp_opcode, 4)),
                }
            };

            if external_port < MIN_ALLOWED_PORT {
                return Some(build_error_response(resp_opcode, 2));
            }

            let capped_lifetime = lifetime.min(MAX_LIFETIME);

            // Delete mapping
            if capped_lifetime == 0 {
                let key = MappingKey {
                    protocol,
                    external_port,
                };
                mappings.remove(&key);
                reload_anchor_rules(ext_ifname, mappings).await;
                return Some(build_mapping_response(
                    resp_opcode,
                    sssoe,
                    internal_port,
                    external_port,
                    0,
                ));
            }

            // Add/update mapping
            let key = MappingKey {
                protocol,
                external_port,
            };
            let mapping = Mapping {
                internal_ip: client_ip,
                internal_port,
                external_port,
                protocol,
                lifetime_secs: capped_lifetime,
                created_at: Instant::now(),
            };
            mappings.insert(key, mapping);
            reload_anchor_rules(ext_ifname, mappings).await;

            Some(build_mapping_response(
                resp_opcode,
                sssoe,
                internal_port,
                external_port,
                capped_lifetime,
            ))
        }
        _ => Some(build_error_response(RESPONSE_FLAG + opcode, 5)), // Unsupported opcode
    }
}

/// Build opcode 0 response: external address.
fn build_external_address_response(sssoe: u32, ip: Ipv4Addr) -> Vec<u8> {
    let mut resp = Vec::with_capacity(12);
    resp.push(0); // version
    resp.push(RESPONSE_FLAG); // response to opcode 0
    resp.extend_from_slice(&0u16.to_be_bytes()); // result code: success
    resp.extend_from_slice(&sssoe.to_be_bytes());
    resp.extend_from_slice(&ip.octets());
    resp
}

/// Build mapping response (opcode 1/2 response).
fn build_mapping_response(
    opcode: u8,
    sssoe: u32,
    internal_port: u16,
    external_port: u16,
    lifetime: u32,
) -> Vec<u8> {
    let mut resp = Vec::with_capacity(16);
    resp.push(0); // version
    resp.push(opcode);
    resp.extend_from_slice(&0u16.to_be_bytes()); // result code: success
    resp.extend_from_slice(&sssoe.to_be_bytes());
    resp.extend_from_slice(&internal_port.to_be_bytes());
    resp.extend_from_slice(&external_port.to_be_bytes());
    resp.extend_from_slice(&lifetime.to_be_bytes());
    resp
}

/// Build an error response.
fn build_error_response(opcode: u8, result_code: u16) -> Vec<u8> {
    let mut resp = Vec::with_capacity(8);
    resp.push(0); // version
    resp.push(opcode);
    resp.extend_from_slice(&result_code.to_be_bytes());
    resp.extend_from_slice(&0u32.to_be_bytes()); // sssoe = 0 on error
    resp
}

/// Find an available external port for a mapping.
fn find_available_port(mappings: &HashMap<MappingKey, Mapping>, protocol: Protocol) -> Option<u16> {
    for port in MIN_ALLOWED_PORT..=65535 {
        let key = MappingKey {
            protocol,
            external_port: port,
        };
        if !mappings.contains_key(&key) {
            return Some(port);
        }
    }
    None
}

/// Get the IPv4 address of a network interface.
async fn get_interface_ip(ifname: &str) -> Option<Ipv4Addr> {
    let output = Command::new("ifconfig").arg(ifname).output().await.ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("inet ") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                return parts[1].parse().ok();
            }
        }
    }
    None
}

/// Reload the pf anchor with current mappings.
async fn reload_anchor_rules(ext_ifname: &str, mappings: &HashMap<MappingKey, Mapping>) {
    if mappings.is_empty() {
        flush_anchor_rules().await;
        return;
    }

    let mut rules = String::new();
    for mapping in mappings.values() {
        // rdr rule: redirect incoming traffic to internal host
        rules.push_str(&format!(
            "rdr pass on {} proto {} from any to any port {} -> {} port {}\n",
            ext_ifname,
            mapping.protocol,
            mapping.external_port,
            mapping.internal_ip,
            mapping.internal_port,
        ));
        // pass rule: allow the redirected traffic
        rules.push_str(&format!(
            "pass in quick on {} proto {} from any to {} port {}\n",
            ext_ifname, mapping.protocol, mapping.internal_ip, mapping.internal_port,
        ));
    }

    let mut child = match Command::new("pfctl")
        .args(["-a", PF_ANCHOR_NAME, "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return,
    };

    if let Some(ref mut stdin) = child.stdin {
        let _ = stdin.write_all(rules.as_bytes()).await;
        let _ = stdin.shutdown().await;
    }

    let _ = child.wait().await;
}

/// Flush all rules from the natpmp anchor.
async fn flush_anchor_rules() {
    let _ = Command::new("pfctl")
        .args(["-a", PF_ANCHOR_NAME, "-F", "all"])
        .output()
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_from_ip() {
        assert_eq!(
            NatPmpServer::network_from_ip(Ipv4Addr::new(192, 168, 2, 1)),
            "192.168.2.0/24"
        );
        assert_eq!(
            NatPmpServer::network_from_ip(Ipv4Addr::new(10, 0, 0, 1)),
            "10.0.0.0/24"
        );
    }

    #[test]
    fn test_build_external_address_response() {
        let ip = Ipv4Addr::new(10, 8, 0, 1);
        let resp = build_external_address_response(42, ip);
        assert_eq!(resp.len(), 12);
        assert_eq!(resp[0], 0); // version
        assert_eq!(resp[1], RESPONSE_FLAG); // response opcode
        assert_eq!(u16::from_be_bytes([resp[2], resp[3]]), 0); // success
        assert_eq!(u32::from_be_bytes([resp[4], resp[5], resp[6], resp[7]]), 42); // sssoe
        assert_eq!(&resp[8..12], &[10, 8, 0, 1]); // IP
    }

    #[test]
    fn test_build_mapping_response() {
        let resp = build_mapping_response(129, 100, 8080, 8080, 3600);
        assert_eq!(resp.len(), 16);
        assert_eq!(resp[0], 0); // version
        assert_eq!(resp[1], 129); // response opcode (UDP)
        assert_eq!(u16::from_be_bytes([resp[2], resp[3]]), 0); // success
        assert_eq!(
            u32::from_be_bytes([resp[4], resp[5], resp[6], resp[7]]),
            100
        ); // sssoe
        assert_eq!(u16::from_be_bytes([resp[8], resp[9]]), 8080); // internal port
        assert_eq!(u16::from_be_bytes([resp[10], resp[11]]), 8080); // external port
        assert_eq!(
            u32::from_be_bytes([resp[12], resp[13], resp[14], resp[15]]),
            3600
        ); // lifetime
    }

    #[test]
    fn test_build_error_response() {
        let resp = build_error_response(RESPONSE_FLAG + 1, 5);
        assert_eq!(resp.len(), 8);
        assert_eq!(resp[0], 0); // version
        assert_eq!(resp[1], RESPONSE_FLAG + 1); // response opcode
        assert_eq!(u16::from_be_bytes([resp[2], resp[3]]), 5); // result code
        assert_eq!(u32::from_be_bytes([resp[4], resp[5], resp[6], resp[7]]), 0);
        // sssoe
    }

    #[test]
    fn test_find_available_port() {
        let mappings = HashMap::new();
        assert_eq!(
            find_available_port(&mappings, Protocol::Tcp),
            Some(MIN_ALLOWED_PORT)
        );

        let mut mappings = HashMap::new();
        mappings.insert(
            MappingKey {
                protocol: Protocol::Tcp,
                external_port: 1024,
            },
            Mapping {
                internal_ip: Ipv4Addr::new(192, 168, 2, 100),
                internal_port: 8080,
                external_port: 1024,
                protocol: Protocol::Tcp,
                lifetime_secs: 3600,
                created_at: Instant::now(),
            },
        );
        assert_eq!(find_available_port(&mappings, Protocol::Tcp), Some(1025));
        // UDP should still find 1024 since it's a different protocol
        assert_eq!(find_available_port(&mappings, Protocol::Udp), Some(1024));
    }

    #[test]
    fn test_is_lan_client() {
        let lan = "192.168.2.0/24";

        let on_lan = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 2, 100), 12345));
        assert!(is_lan_client(&on_lan, lan));

        let off_lan = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 12345));
        assert!(!is_lan_client(&off_lan, lan));

        let boundary = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 3, 1), 12345));
        assert!(!is_lan_client(&boundary, lan));
    }

    #[test]
    fn test_mapping_expiry() {
        let mapping = Mapping {
            internal_ip: Ipv4Addr::new(192, 168, 2, 100),
            internal_port: 8080,
            external_port: 8080,
            protocol: Protocol::Tcp,
            lifetime_secs: 0, // Expired immediately
            created_at: Instant::now(),
        };
        assert!(mapping.is_expired());

        let mapping = Mapping {
            internal_ip: Ipv4Addr::new(192, 168, 2, 100),
            internal_port: 8080,
            external_port: 8080,
            protocol: Protocol::Tcp,
            lifetime_secs: 3600,
            created_at: Instant::now(),
        };
        assert!(!mapping.is_expired());
    }
}
