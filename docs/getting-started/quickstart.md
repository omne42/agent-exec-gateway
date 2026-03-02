# Quickstart

## 1. Add Dependency

```toml
[dependencies]
agent-exec-gateway = { path = "../agent-exec-gateway" }
```

## 2. Minimal Rust Example

```rust
use agent_exec_gateway::{ExecGateway, ExecRequest, IsolationLevel};

let gateway = ExecGateway::new();
let req = ExecRequest::new(
    "sh",
    ["-lc", "echo hello"],
    ".",
    IsolationLevel::BestEffort,
    ".",
);

let status = gateway.execute_status(&req)?;
assert!(status.success());
# Ok::<(), agent_exec_gateway::ExecError>(())
```

## 3. Check Host Capability

```bash
cargo run --bin capability
```

Example output:

```text
supported_isolation=BestEffort
```

## 4. Optional CLI Mode

```bash
cargo run --bin agent-exec -- --policy ./policy.json --request ./request.json
```

`agent-exec` prints one JSON result object with decision, reason, isolation info, and exit outcome.

## 5. Common Failure Cases

- `cwd` outside `workspace_root` -> denied.
- requested `strict` above host support -> denied.
- mutating request with non-allowlisted program -> denied (when policy enforcement is on).
