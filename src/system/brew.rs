//! Homebrew detection. Used by the in-app dnsmasq installer to decide
//! whether `brew install dnsmasq` is even runnable.

use std::path::Path;
use std::process::Command as SyncCommand;

/// Locate the `brew` binary. Mirrors [`crate::system::dhcp::DhcpServer::find_dnsmasq`] —
/// checks Apple Silicon and Intel Homebrew prefixes first (sudo's `PATH`
/// doesn't typically include them), then falls back to `which brew`.
pub fn find_brew() -> Option<String> {
    let common_paths = ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"];

    for path in common_paths {
        if Path::new(path).exists() {
            return Some(path.to_string());
        }
    }

    SyncCommand::new("which")
        .arg("brew")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn brew_installed() -> bool {
    find_brew().is_some()
}
