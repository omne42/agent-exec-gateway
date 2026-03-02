# AI and Agent Integration

Use `agent-exec-gateway` as the command execution boundary in agent loops.

## Recommended Flow

```text
agent plan
-> build ExecRequest
-> set declared_mutation explicitly
-> evaluate (optional)
-> execute_status_with_event
-> store event + process result
-> feed summarized result back to planner
```

## Integration Rules

- Always supply explicit isolation enum values.
- Always set `declared_mutation` intentionally.
- Keep `workspace_root` explicit and stable.
- Treat denial reasons as actionable control signals.

## Repair Mapping

| Reason | Typical remediation |
| --- | --- |
| `isolation_not_supported` | Lower isolation only with explicit approval. |
| `cwd_outside_workspace` | Correct path under workspace root. |
| `mutation_requires_fs_tool` | Route via `safe-fs-tools`. |
| `isolation_none_forbidden` | Use `best_effort` or `strict`. |

## Safe Defaults for Autonomous Runs

- `allow_isolation_none=false`
- `enforce_fs_tool_for_mutation=true`
- request `best_effort` by default
- keep audit logging enabled
