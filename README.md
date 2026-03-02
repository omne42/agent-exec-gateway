# agent-exec-gateway

Cross-platform command execution gateway for agent runtimes and tooling, with explicit isolation semantics and fail-closed policy enforcement.

## Why This Exists

`agent-exec-gateway` provides one consistent execution boundary for `program + args + cwd` command calls.

It prevents fragmented per-caller safety logic and provides deterministic decisions with structured audit data.

## Core Guarantees

- capability model: `None | BestEffort | Strict`
- fail-closed if requested isolation exceeds host support
- workspace boundary enforcement (`cwd` must be inside `workspace_root`)
- optional mutating-command enforcement via allowlisted filesystem tool programs
- structured decision events for audit/logging

## Platform Capability (v0.1.0)

- Linux: detects Landlock support at runtime; `Strict` when available, otherwise `BestEffort`
- macOS: `BestEffort`
- Windows: `BestEffort`

If `Strict` is requested but unsupported, execution is denied (no silent downgrade).

## Quick Usage

```rust
use agent_exec_gateway::{ExecGateway, ExecRequest, IsolationLevel};

let gateway = ExecGateway::new();
let req = ExecRequest::new(
    "sh",
    vec!["-lc", "echo hello"],
    ".",
    IsolationLevel::BestEffort,
    ".",
);
let status = gateway.execute_status(&req)?;
assert!(status.success());
# Ok::<(), agent_exec_gateway::ExecError>(())
```

## Capability Check

```bash
cargo run --bin capability
```

## CLI Adapter

```bash
cargo run --bin agent-exec -- --policy ./policy.json --request ./request.json
```

## Documentation

- docs source: `docs/`
- site config: `mkdocs.yml`
- auto deployment: `.github/workflows/docs-pages.yml`

GitHub Pages deployment is fully automated via GitHub Actions and includes version selection (powered by `mike`).
