use std::path::Path;
use std::process::Command;

use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus,
};
use std::io;
use std::os::unix::process::CommandExt;

use crate::error::ExecResult;
use crate::types::IsolationLevel;

pub fn detect_supported_isolation() -> IsolationLevel {
    if landlock_strict_is_available() {
        IsolationLevel::Strict
    } else {
        IsolationLevel::BestEffort
    }
}

pub fn apply_sandbox(
    command: &mut Command,
    required_isolation: IsolationLevel,
    workspace_root: &Path,
) -> ExecResult<()> {
    match required_isolation {
        IsolationLevel::None | IsolationLevel::BestEffort => {
            // Best-effort marker for downstream audit/logging.
            command.env("AGENT_EXEC_GATEWAY_WORKSPACE_ROOT", workspace_root);
            Ok(())
        }
        IsolationLevel::Strict => {
            let workspace_root = workspace_root.to_path_buf();
            let workspace_root_for_pre_exec = workspace_root.clone();
            // SAFETY:
            // `pre_exec` runs in the child after fork and before exec. The closure only
            // performs deterministic setup (Landlock + env var update) and returns an I/O
            // error to abort execution on failure.
            unsafe {
                command.pre_exec(move || {
                    apply_landlock_strict(&workspace_root_for_pre_exec)?;
                    Ok(())
                });
            }
            command.env("AGENT_EXEC_GATEWAY_WORKSPACE_ROOT", workspace_root);
            Ok(())
        }
    }
}

fn landlock_strict_is_available() -> bool {
    let abi = ABI::V6;
    let ruleset = match Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(abi))
    {
        Ok(ruleset) => ruleset,
        Err(_) => return false,
    };
    ruleset.create().is_ok()
}

fn apply_landlock_strict(workspace_root: &Path) -> io::Result<()> {
    let abi = ABI::V6;
    let all_access = AccessFs::from_all(abi);
    let read_access = AccessFs::from_read(abi) | AccessFs::Execute;
    let created = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(all_access)
        .map_err(to_io_error)?
        .create()
        .map_err(to_io_error)?;

    let status = created
        .add_rule(PathBeneath::new(
            PathFd::new("/").map_err(to_io_error)?,
            read_access,
        ))
        .map_err(to_io_error)?
        .add_rule(PathBeneath::new(
            PathFd::new(workspace_root).map_err(to_io_error)?,
            all_access,
        ))
        .map_err(to_io_error)?
        .restrict_self()
        .map_err(to_io_error)?;

    if status.ruleset != RulesetStatus::FullyEnforced {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("landlock not fully enforced: {:?}", status.ruleset),
        ));
    }

    Ok(())
}

fn to_io_error(err: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, err.to_string())
}
