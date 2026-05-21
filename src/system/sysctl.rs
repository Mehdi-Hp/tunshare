//! IP forwarding control via sysctl.

use crate::error::{Result, TunshareError};
use crate::system::run_cmd;
use std::process::Command as SyncCommand;

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
        let output = run_cmd("sysctl", &["-n", "net.inet.ip.forwarding"]).await?;

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

    /// Restore the original IP forwarding state (async wrapper).
    /// Delegates to `restore_sync` via `spawn_blocking`.
    pub async fn restore(&mut self) -> Result<()> {
        if let Some(original) = self.original_state.take() {
            tokio::task::spawn_blocking(move || set_state_sync(original))
                .await
                .map_err(|e| TunshareError::CommandFailed {
                    command: "restore (spawn_blocking)".into(),
                    message: e.to_string(),
                })??;
        }
        Ok(())
    }

    async fn set_state(&self, enabled: bool) -> Result<()> {
        tokio::task::spawn_blocking(move || set_state_sync(enabled))
            .await
            .map_err(|e| TunshareError::CommandFailed {
                command: "set_state (spawn_blocking)".into(),
                message: e.to_string(),
            })?
    }

    /// Returns whether we have saved the original state (meaning we've modified it).
    pub fn is_modified(&self) -> bool {
        self.original_state.is_some()
    }

    /// Synchronous restore for use in Drop.
    pub fn restore_sync(&mut self) {
        if let Some(original) = self.original_state.take() {
            let _ = set_state_sync(original);
        }
    }
}

impl Default for IpForwarding {
    fn default() -> Self {
        Self::new()
    }
}

/// Standalone sync implementation for setting IP forwarding state.
/// Single source of truth for both sync and async paths.
fn set_state_sync(enabled: bool) -> Result<()> {
    let value = if enabled { "1" } else { "0" };
    let output = SyncCommand::new("sysctl")
        .arg("-w")
        .arg(format!("net.inet.ip.forwarding={}", value))
        .output()
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
