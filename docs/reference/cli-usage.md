# CLI Usage

Use `agent-exec` as a policy-enforcing CLI adapter.

## Command

```bash
cargo run --bin agent-exec -- --policy ./policy.json --request ./request.json
```

## policy.json

```json
{
  "allow_isolation_none": false,
  "enforce_fs_tool_for_mutation": true,
  "fs_tool_program_allowlist": ["safe-fs-tools", "safe-fs-tools-cli"],
  "default_isolation": "best_effort",
  "audit_log_path": "/tmp/agent_exec_audit.jsonl"
}
```

## request.json

```json
{
  "program": "sh",
  "args": ["-lc", "echo hello-from-agent-exec"],
  "cwd": ".",
  "workspace_root": ".",
  "required_isolation": "best_effort",
  "declared_mutation": false
}
```

`required_isolation` is optional; when omitted, `default_isolation` is applied.

## Output Schema

One JSON line with:

- `decision`
- `reason`
- `requested_isolation`
- `supported_isolation`
- `exit_code`
- `error`

## Exit Behavior

- exit `0` only when command exits `0`.
- non-zero for deny/failure/non-zero child exit.
