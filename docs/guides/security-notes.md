# Security Notes

`agent-exec-gateway` improves execution safety, but it is one control layer in a broader security stack.

## What It Enforces

- isolation capability checks,
- workspace boundary checks,
- mutation allowlist for declared mutating requests.

## What It Does Not Enforce Alone

- command intent semantics,
- network isolation,
- secret isolation across subprocesses,
- binary provenance verification.

## Operational Recommendations

- run under least-privilege OS accounts,
- keep workspace roots narrow,
- enable audit logging in production,
- pair with dedicated filesystem safety tooling,
- treat `none` isolation as exceptional.
