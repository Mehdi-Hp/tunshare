//! System interaction modules for network, firewall, DNS, DHCP, and sysctl operations.

pub mod brew;
pub mod dhcp;
pub mod dns;
pub mod firewall;
pub mod natpmp;
pub mod network;
pub mod pmtu;
pub mod sysctl;
pub mod traffic;

pub use brew::brew_installed;
pub use dhcp::DhcpServer;
pub use dns::discover_vpn_dns;
pub use firewall::Firewall;
pub use natpmp::NatPmpServer;
pub use network::{
    default_route_interface, detect_lan_interfaces, detect_vpn_interfaces, read_mtu,
    same_ipv4_network, InterfaceInfo,
};
pub use pmtu::{probe_path_mtu, CONSERVATIVE_MTU};
pub use sysctl::IpForwarding;
pub use traffic::{read_interface_bytes, InterfaceBytes};

use crate::error::{Result, TunshareError};

/// Run a command and return its `Output`. The error includes the full
/// command line so callers don't have to repeat themselves.
///
/// Only spawn-and-output cases — for stdin-piped or fire-and-forget cases,
/// keep using the raw API.
pub(crate) async fn run_cmd(program: &str, args: &[&str]) -> Result<std::process::Output> {
    tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
        .map_err(|e| TunshareError::CommandFailed {
            command: format!("{} {}", program, args.join(" ")),
            message: e.to_string(),
        })
}
