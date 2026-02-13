//! Error types for VPN sharing operations.

use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum TunshareError {
    #[error("Command failed: {command} - {message}")]
    CommandFailed { command: String, message: String },

    #[error("No VPN interfaces found. Is your VPN connected?")]
    NoVpnInterfaces,

    #[error("No LAN interfaces found")]
    NoLanInterfaces,

    #[error("Permission denied. Run with sudo.")]
    PermissionDenied,

    #[error("Failed to parse output: {0}")]
    ParseError(String),

    #[error("Firewall error: {0}")]
    FirewallError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, TunshareError>;
