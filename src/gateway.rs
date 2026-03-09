use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use crate::audit::{ExecDecision, ExecEvent};
use crate::audit_log::AuditLogger;
use crate::error::{ExecError, ExecResult};
use crate::policy::GatewayPolicy;
use crate::sandbox;
use crate::types::{ExecRequest, IsolationLevel};

#[derive(Debug)]
pub struct ExecGateway {
    supported_isolation: IsolationLevel,
    policy: GatewayPolicy,
    audit: Option<AuditLogger>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityReport {
    pub supported_isolation: IsolationLevel,
    pub policy_default_isolation: IsolationLevel,
}

impl Default for ExecGateway {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecGateway {
    pub fn new() -> Self {
        let policy = GatewayPolicy::default();
        Self::with_policy_and_supported_isolation(policy, sandbox::detect_supported_isolation())
    }

    pub fn with_policy(policy: GatewayPolicy) -> Self {
        Self::with_policy_and_supported_isolation(policy, sandbox::detect_supported_isolation())
    }

    pub fn with_policy_and_supported_isolation(
        policy: GatewayPolicy,
        supported_isolation: IsolationLevel,
    ) -> Self {
        let audit = policy.audit_log_path.as_ref().map(AuditLogger::new);
        Self {
            supported_isolation,
            policy,
            audit,
        }
    }

    pub fn with_supported_isolation(supported_isolation: IsolationLevel) -> Self {
        Self::with_policy_and_supported_isolation(GatewayPolicy::default(), supported_isolation)
    }

    pub fn supported_isolation(&self) -> IsolationLevel {
        self.supported_isolation
    }

    pub fn policy(&self) -> &GatewayPolicy {
        &self.policy
    }

    pub fn capability_report(&self) -> CapabilityReport {
        CapabilityReport {
            supported_isolation: self.supported_isolation,
            policy_default_isolation: self.policy.default_isolation,
        }
    }

    pub fn evaluate(&self, request: &ExecRequest) -> ExecEvent {
        let mut event = ExecEvent {
            decision: ExecDecision::Run,
            requested_isolation: request.required_isolation,
            supported_isolation: self.supported_isolation,
            program: request.program.clone(),
            cwd: request.cwd.clone(),
            workspace_root: request.workspace_root.clone(),
            declared_mutation: request.declared_mutation,
            reason: None,
        };

        if matches!(request.required_isolation, IsolationLevel::None)
            && !self.policy.allow_isolation_none
        {
            event.decision = ExecDecision::Deny;
            event.reason = Some("isolation_none_forbidden".to_string());
            return event;
        }

        if request.declared_mutation && self.policy.enforce_fs_tool_for_mutation {
            let program = request.program.to_string_lossy();
            if !self.policy.is_fs_tool_program(&program) {
                event.decision = ExecDecision::Deny;
                event.reason = Some("mutation_requires_fs_tool".to_string());
                return event;
            }
        }

        if request.required_isolation > self.supported_isolation {
            event.decision = ExecDecision::Deny;
            event.reason = Some("isolation_not_supported".to_string());
            return event;
        }

        let workspace_root = match canonicalize_workspace_root(&request.workspace_root) {
            Ok(path) => path,
            Err(_) => {
                event.decision = ExecDecision::Deny;
                event.reason = Some("workspace_root_invalid".to_string());
                return event;
            }
        };

        match ensure_cwd_within_workspace(&request.cwd, &workspace_root) {
            Ok(()) => event,
            Err(_) => {
                event.decision = ExecDecision::Deny;
                event.reason = Some("cwd_outside_workspace".to_string());
                event
            }
        }
    }

    pub fn execute_status(&self, request: &ExecRequest) -> ExecResult<ExitStatus> {
        let mut command = Command::new(&request.program);
        command.args(&request.args);
        let (_event, prepare_result) = self.prepare_command(request, &mut command);
        prepare_result?;
        command.status().map_err(ExecError::Spawn)
    }

    pub fn execute_status_with_event(
        &self,
        request: &ExecRequest,
    ) -> (ExecEvent, ExecResult<ExitStatus>) {
        let mut command = Command::new(&request.program);
        command.args(&request.args);
        let (event, prepare_result) = self.prepare_command(request, &mut command);
        let result = prepare_result.and_then(|_| command.status().map_err(ExecError::Spawn));
        (event, result)
    }

    pub fn prepare_command(
        &self,
        request: &ExecRequest,
        command: &mut Command,
    ) -> (ExecEvent, ExecResult<()>) {
        let event = self.evaluate(request);
        let result = self.prepare_command_inner(request, command);
        if let Some(audit) = &self.audit {
            let status = match result.as_ref() {
                Ok(_) => Ok(()),
                Err(err) => Err(err),
            };
            audit.write_record(&event, &status);
        }
        (event, result)
    }

    fn prepare_command_inner(
        &self,
        request: &ExecRequest,
        command: &mut Command,
    ) -> ExecResult<()> {
        if matches!(request.required_isolation, IsolationLevel::None)
            && !self.policy.allow_isolation_none
        {
            return Err(ExecError::PolicyDenied(
                "isolation none is forbidden by policy".to_string(),
            ));
        }
        if request.declared_mutation && self.policy.enforce_fs_tool_for_mutation {
            let program = request.program.to_string_lossy();
            if !self.policy.is_fs_tool_program(&program) {
                return Err(ExecError::PolicyDenied(
                    "declared mutating command must use safe-fs-tools".to_string(),
                ));
            }
        }
        self.ensure_isolation_supported(request.required_isolation)?;
        let workspace_root = canonicalize_workspace_root(&request.workspace_root)?;
        ensure_cwd_within_workspace(&request.cwd, &workspace_root)?;
        command.current_dir(&request.cwd);
        sandbox::apply_sandbox(command, request.required_isolation, &workspace_root)?;
        Ok(())
    }

    fn ensure_isolation_supported(&self, requested: IsolationLevel) -> ExecResult<()> {
        if requested > self.supported_isolation {
            return Err(ExecError::IsolationNotSupported {
                requested,
                supported: self.supported_isolation,
            });
        }
        Ok(())
    }
}

fn canonicalize_workspace_root(path: &Path) -> ExecResult<PathBuf> {
    path.canonicalize()
        .map_err(|_| ExecError::WorkspaceRootInvalid {
            path: path.to_path_buf(),
        })
}

fn ensure_cwd_within_workspace(cwd: &Path, workspace_root: &Path) -> ExecResult<()> {
    let cwd = cwd
        .canonicalize()
        .map_err(|_| ExecError::CwdOutsideWorkspace {
            cwd: cwd.to_path_buf(),
            workspace_root: workspace_root.to_path_buf(),
        })?;

    if !cwd.starts_with(workspace_root) {
        return Err(ExecError::CwdOutsideWorkspace {
            cwd,
            workspace_root: workspace_root.to_path_buf(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use tempfile::tempdir;

    use super::*;
    use crate::policy::GatewayPolicy;

    #[test]
    fn fail_closed_when_required_isolation_exceeds_supported() {
        let gateway = ExecGateway::with_supported_isolation(IsolationLevel::BestEffort);
        let workspace = tempdir().expect("create temp workspace");

        let request = ExecRequest::new(
            OsString::from(dummy_program()),
            Vec::<OsString>::new(),
            workspace.path(),
            IsolationLevel::Strict,
            workspace.path(),
        );

        let err = gateway
            .execute_status(&request)
            .expect_err("strict request should fail closed");

        match err {
            ExecError::IsolationNotSupported {
                requested,
                supported,
            } => {
                assert_eq!(requested, IsolationLevel::Strict);
                assert_eq!(supported, IsolationLevel::BestEffort);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn rejects_cwd_outside_workspace() {
        let gateway = ExecGateway::with_supported_isolation(IsolationLevel::BestEffort);
        let workspace = tempdir().expect("create temp workspace");
        let outside = tempdir().expect("create outside cwd");

        let request = ExecRequest::new(
            OsString::from(dummy_program()),
            Vec::<OsString>::new(),
            outside.path(),
            IsolationLevel::BestEffort,
            workspace.path(),
        );

        let err = gateway
            .execute_status(&request)
            .expect_err("outside cwd should be blocked");

        match err {
            ExecError::CwdOutsideWorkspace { .. } => {}
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn supports_none_even_when_host_is_none() {
        let policy = GatewayPolicy {
            allow_isolation_none: true,
            ..GatewayPolicy::default()
        };
        let gateway =
            ExecGateway::with_policy_and_supported_isolation(policy, IsolationLevel::None);
        let workspace = tempdir().expect("create temp workspace");

        let request = ExecRequest::new(
            OsString::from(dummy_program()),
            Vec::<OsString>::new(),
            workspace.path(),
            IsolationLevel::None,
            workspace.path(),
        );

        let err = gateway.execute_status(&request);
        assert!(err.is_ok() || matches!(err, Err(ExecError::Spawn(_))));
    }

    #[test]
    fn evaluate_denies_with_reason_for_unsupported_isolation() {
        let gateway = ExecGateway::with_supported_isolation(IsolationLevel::BestEffort);
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            dummy_program(),
            Vec::<OsString>::new(),
            workspace.path(),
            IsolationLevel::Strict,
            workspace.path(),
        );

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(event.reason.as_deref(), Some("isolation_not_supported"));
    }

    #[test]
    fn capability_report_matches_supported_isolation() {
        let gateway = ExecGateway::with_supported_isolation(IsolationLevel::BestEffort);
        let report = gateway.capability_report();
        assert_eq!(report.supported_isolation, IsolationLevel::BestEffort);
        assert_eq!(report.policy_default_isolation, IsolationLevel::BestEffort);
    }

    #[test]
    fn execute_with_event_preserves_deny_reason() {
        let gateway = ExecGateway::with_supported_isolation(IsolationLevel::BestEffort);
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            dummy_program(),
            Vec::<OsString>::new(),
            workspace.path(),
            IsolationLevel::Strict,
            workspace.path(),
        );

        let (event, result) = gateway.execute_status_with_event(&request);
        assert_eq!(event.reason.as_deref(), Some("isolation_not_supported"));
        assert!(result.is_err());
    }

    #[test]
    fn denies_mutation_for_non_fs_tool_program() {
        let gateway = ExecGateway::with_supported_isolation(IsolationLevel::BestEffort);
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            dummy_program(),
            Vec::<OsString>::new(),
            workspace.path(),
            IsolationLevel::BestEffort,
            workspace.path(),
        )
        .with_declared_mutation(true);
        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(event.reason.as_deref(), Some("mutation_requires_fs_tool"));
    }

    #[test]
    fn allows_mutation_for_allowlisted_fs_tool_program() {
        let gateway = ExecGateway::with_supported_isolation(IsolationLevel::BestEffort);
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            "safe-fs-tools",
            Vec::<OsString>::new(),
            workspace.path(),
            IsolationLevel::BestEffort,
            workspace.path(),
        )
        .with_declared_mutation(true);
        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Run);
    }

    #[test]
    fn denies_none_isolation_by_default_policy() {
        let gateway = ExecGateway::with_supported_isolation(IsolationLevel::BestEffort);
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            "safe-fs-tools",
            Vec::<OsString>::new(),
            workspace.path(),
            IsolationLevel::None,
            workspace.path(),
        );
        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(event.reason.as_deref(), Some("isolation_none_forbidden"));
    }

    #[test]
    fn prepare_command_sets_current_dir() {
        let policy = GatewayPolicy {
            allow_isolation_none: true,
            ..GatewayPolicy::default()
        };
        let gateway =
            ExecGateway::with_policy_and_supported_isolation(policy, IsolationLevel::BestEffort);
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            "echo",
            vec!["hello"],
            workspace.path(),
            IsolationLevel::BestEffort,
            workspace.path(),
        );
        let mut command = Command::new("echo");
        command.arg("hello");
        let (_event, result) = gateway.prepare_command(&request, &mut command);
        assert!(result.is_ok());
    }

    #[cfg(windows)]
    fn dummy_program() -> &'static str {
        "cmd"
    }

    #[cfg(not(windows))]
    fn dummy_program() -> &'static str {
        "sh"
    }
}
