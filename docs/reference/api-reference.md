# API Reference

## Main Re-exports

- `ExecGateway`
- `ExecRequest`
- `IsolationLevel`
- `ExecDecision`
- `ExecEvent`
- `ExecError`
- `ExecResult`
- `CapabilityReport`

## ExecRequest

```rust
ExecRequest::new(program, args, cwd, required_isolation, workspace_root)
  .with_declared_mutation(bool)
```

Fields:

- `program: OsString`
- `args: Vec<OsString>`
- `cwd: PathBuf`
- `required_isolation: IsolationLevel`
- `workspace_root: PathBuf`
- `declared_mutation: bool`

## ExecGateway Constructors

- `ExecGateway::new()`
- `ExecGateway::with_policy(policy)`
- `ExecGateway::with_supported_isolation(level)`
- `ExecGateway::with_policy_and_supported_isolation(policy, level)`

## ExecGateway Methods

- `supported_isolation()`
- `policy()`
- `capability_report()`
- `evaluate(&ExecRequest)`
- `execute_status(&ExecRequest)`
- `execute_status_with_event(&ExecRequest)`
- `prepare_command(&ExecRequest, &mut Command)`

## GatewayPolicy

Path: `agent_exec_gateway::policy::GatewayPolicy`

- `GatewayPolicy::default()`
- `GatewayPolicy::load_json(path)`
- `is_fs_tool_program(program)`

## ExecError Variants

- `IsolationNotSupported { requested, supported }`
- `WorkspaceRootInvalid { path }`
- `CwdOutsideWorkspace { cwd, workspace_root }`
- `Sandbox(String)`
- `PolicyDenied(String)`
- `Spawn(io::Error)`
