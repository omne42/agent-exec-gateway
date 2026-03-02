use std::path::Path;
use std::process::Command;

use crate::error::{ExecError, ExecResult};
use crate::types::IsolationLevel;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

pub fn detect_supported_isolation() -> IsolationLevel {
    #[cfg(target_os = "linux")]
    {
        return linux::detect_supported_isolation();
    }

    #[cfg(target_os = "macos")]
    {
        return macos::detect_supported_isolation();
    }

    #[cfg(target_os = "windows")]
    {
        return windows::detect_supported_isolation();
    }

    #[allow(unreachable_code)]
    IsolationLevel::None
}

pub fn apply_sandbox(
    command: &mut Command,
    required_isolation: IsolationLevel,
    workspace_root: &Path,
) -> ExecResult<()> {
    #[cfg(target_os = "linux")]
    {
        return linux::apply_sandbox(command, required_isolation, workspace_root);
    }

    #[cfg(target_os = "macos")]
    {
        return macos::apply_sandbox(command, required_isolation, workspace_root);
    }

    #[cfg(target_os = "windows")]
    {
        return windows::apply_sandbox(command, required_isolation, workspace_root);
    }

    #[allow(unreachable_code)]
    match required_isolation {
        IsolationLevel::None => Ok(()),
        _ => Err(ExecError::Sandbox(
            "sandbox not supported on this platform".to_string(),
        )),
    }
}
