# Audit Events

The gateway exposes `ExecEvent` to describe decision outcomes.

## Event Fields

| Field | Description |
| --- | --- |
| `decision` | `run` or `deny`. |
| `requested_isolation` | Isolation requested by caller. |
| `supported_isolation` | Host-supported isolation detected by gateway. |
| `program` | Program name (serialized lossily for OS strings). |
| `cwd` | Requested working directory. |
| `workspace_root` | Workspace boundary root. |
| `declared_mutation` | Caller-declared mutation intent. |
| `reason` | Optional denial reason. |

## API Entry Points

- `evaluate(&request)` for dry-run decision check.
- `execute_status_with_event(&request)` for decision plus execution result.

## JSONL Audit Sink

When `audit_log_path` is set, the gateway appends JSONL records with:

- `ts_unix_ms`
- full `event`
- `result.status` (`ok` or `error`)
- `result.error` (if present)
