# Isolation Semantics

The gateway uses three isolation levels from `policy-meta`.

| Level | Meaning |
| --- | --- |
| `none` | No isolation guarantee. |
| `best_effort` | Attempted boundary with limited guarantees. |
| `strict` | Strong isolation guarantee expected by caller. |

## Platform Support (v0.1.0)

| Platform | Detected Support | Notes |
| --- | --- | --- |
| Linux | `strict` when Landlock is available, else `best_effort` | Strict path requires Landlock full enforcement. |
| macOS | `best_effort` | Native strict not available. |
| Windows | `best_effort` | Native strict not available. |

## Fail-Closed Behavior

When `required_isolation > supported_isolation`, execution is denied.

No silent downgrade is performed.

## Linux Strict Path

In strict mode on Linux:

- ruleset is installed in child `pre_exec`,
- root read/execute + workspace full access are configured,
- run is rejected if ruleset is not fully enforced.
