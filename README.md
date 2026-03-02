# agent-exec-gateway

跨平台 Agent 终端执行网关（独立于 `safe-fs-tools`）。

## 目标边界

- 统一收口第三方命令执行（`program + args + cwd`）。
- 使用能力分级模型：`None` / `BestEffort` / `Strict`。
- 能力不足时 fail-closed（拒绝执行），不做静默降级。
- 明确这是执行层；文件写操作策略应由 `safe-fs-tools` 处理。

## 当前平台能力（v0.1.0）

- Linux: 运行时探测 Landlock；可用时 `Strict`，否则 `BestEffort`
- macOS: `BestEffort`
- Windows: `BestEffort`

> 在 Linux 上，如果请求 `Strict` 但主机不支持 Landlock，会 fail-closed 拒绝执行。
> 在 macOS/Windows 原生模式下，`Strict` 目前会被拒绝，不做虚假承诺。

## 能力自检

```bash
cargo run --bin capability
```

## 最小示例

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

## 审计事件

网关提供 `evaluate()` 和 `execute_status_with_event()`，可直接把决策结果写入审计流水：

- `decision`: `Run` / `Deny`
- `reason`: `isolation_not_supported` / `workspace_root_invalid` / `cwd_outside_workspace` / `isolation_none_forbidden` / `mutation_requires_fs_tool`

## 策略文件

默认策略（JSON）：

```json
{
  "allow_isolation_none": false,
  "enforce_fs_tool_for_mutation": true,
  "fs_tool_program_allowlist": ["safe-fs-tools", "safe-fs-tools-cli"],
  "default_isolation": "best_effort",
  "audit_log_path": "/tmp/agent_exec_audit.jsonl"
}
```

关键点：

- `allow_isolation_none=false`：默认禁止无隔离执行。
- `enforce_fs_tool_for_mutation=true`：声明为写操作的请求，必须由 `safe-fs-tools` 白名单程序执行。
- 这依赖请求中的显式意图 `declared_mutation`，不依赖脆弱的命令字符串猜测。

## 运行入口

新增可执行文件：

```bash
cargo run --bin agent-exec -- --policy ./policy.json --request ./request.json
```

请求文件示例：

```json
{
  "program": "sh",
  "args": ["-lc", "echo hello-from-agent-exec"],
  "cwd": ".",
  "workspace_root": ".",
  "declared_mutation": false
}
```

声明为写操作但不是 `safe-fs-tools` 程序时会被拒绝（fail-closed）。
