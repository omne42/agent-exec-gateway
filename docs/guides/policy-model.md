# Policy Model

`GatewayPolicy` defines execution controls.

## Fields

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `allow_isolation_none` | `bool` | `false` | Allows `IsolationLevel::None` when true. |
| `enforce_fs_tool_for_mutation` | `bool` | `true` | Requires mutating requests to use allowlisted tools. |
| `fs_tool_program_allowlist` | `Vec<String>` | `safe-fs-tools`, `safe-fs-tools-cli` | Allowed program names for declared mutation. |
| `default_isolation` | `IsolationLevel` | `BestEffort` | Fallback isolation for CLI requests when not provided. |
| `audit_log_path` | `Option<PathBuf>` | `None` | Optional JSONL audit file path. |

## Default Policy JSON

```json
{
  "allow_isolation_none": false,
  "enforce_fs_tool_for_mutation": true,
  "fs_tool_program_allowlist": ["safe-fs-tools", "safe-fs-tools-cli"],
  "default_isolation": "best_effort",
  "audit_log_path": "/tmp/agent_exec_audit.jsonl"
}
```

## Enforcement Order

1. Deny `none` isolation if forbidden.
2. Enforce mutation allowlist for `declared_mutation=true`.
3. Deny if requested isolation exceeds host capability.
4. Deny invalid `workspace_root`.
5. Deny `cwd` outside workspace.
6. Apply sandbox and execute.

## Denial Reasons

- `isolation_none_forbidden`
- `mutation_requires_fs_tool`
- `isolation_not_supported`
- `workspace_root_invalid`
- `cwd_outside_workspace`
