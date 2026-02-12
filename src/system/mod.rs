//! System interaction modules for network, firewall, DNS, DHCP, and sysctl operations.

pub mod dhcp;
pub mod dns;
pub mod firewall;
pub mod natpmp;
pub mod network;
pub mod sysctl;

pub use dhcp::DhcpServer;
pub use dns::discover_vpn_dns;
pub use firewall::Firewall;
pub use natpmp::NatPmpServer;
pub use network::{detect_lan_interfaces, detect_vpn_interfaces, InterfaceInfo};
pub use sysctl::IpForwarding;
