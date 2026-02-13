//! IP forwarding control via sysctl.

use crate::error::{Result, TunshareError};
use tokio::process::Command;

/// Manages IP forwarding state.
pub struct IpForwarding {
    /// The original state before we modified it.
    original_state: Option<bool>,
}

impl IpForwarding {
    pub fn new() -> Self {
        Self {
            original_state: None,
        }
    }

    /// Get the current IP forwarding state.
    pub async fn get_state(&self) -> Result<bool> {
        let output = Command::new("sysctl")
            .arg("-n")
            .arg("net.inet.ip.forwarding")
            .output()
            .await
            .map_err(|e| TunshareError::CommandFailed {
                command: "sysctl -n net.inet.ip.forwarding".into(),
                message: e.to_string(),
            })?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let value = stdout.trim();

        match value {
            "1" => Ok(true),
            "0" => Ok(false),
            _ => Err(TunshareError::ParseError(format!(
                "Unexpected sysctl value: {}",
                value
            ))),
        }
    }

    /// Enable IP forwarding, saving the original state.
    pub async fn enable(&mut self) -> Result<()> {
        // Save original state if not already saved
        if self.original_state.is_none() {
            self.original_state = Some(self.get_state().await?);
        }

        self.set_state(true).await
    }

    /// Restore the original IP forwarding state.
    pub async fn restore(&mut self) -> Result<()> {
        if let Some(original) = self.original_state.take() {
            self.set_state(original).await?;
        }
        Ok(())
    }

    /// Disable IP forwarding.
    #[allow(dead_code)]
    pub async fn disable(&self) -> Result<()> {
        self.set_state(false).await
    }

    async fn set_state(&self, enabled: bool) -> Result<()> {
        let value = if enabled { "1" } else { "0" };
        let output = Command::new("sysctl")
            .arg("-w")
            .arg(format!("net.inet.ip.forwarding={}", value))
            .output()
            .await
            .map_err(|e| TunshareError::CommandFailed {
                command: format!("sysctl -w net.inet.ip.forwarding={}", value),
                message: e.to_string(),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("Operation not permitted") || stderr.contains("Permission denied") {
                return Err(TunshareError::PermissionDenied);
            }
            return Err(TunshareError::CommandFailed {
                command: format!("sysctl -w net.inet.ip.forwarding={}", value),
                message: stderr.to_string(),
            });
        }

        Ok(())
    }

    /// Returns whether we have saved the original state (meaning we've modified it).
    pub fn is_modified(&self) -> bool {
        self.original_state.is_some()
    }

    /// Synchronous restore for use in Drop - uses std::process::Command.
    /// This is a fallback for when async restore isn't possible.
    pub fn restore_sync(&mut self) {
        use std::process::Command as SyncCommand;

        if let Some(original) = self.original_state.take() {
            let value = if original { "1" } else { "0" };
            let _ = SyncCommand::new("sysctl")
                .arg("-w")
                .arg(format!("net.inet.ip.forwarding={}", value))
                .output();
        }
    }
}

impl Default for IpForwarding {
    fn default() -> Self {
        Self::new()
    }
}
