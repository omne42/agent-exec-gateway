use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use agent_exec_gateway::policy::GatewayPolicy;
use agent_exec_gateway::{ExecGateway, ExecRequest, IsolationLevel};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct ExecRequestWire {
    program: String,
    #[serde(default)]
    args: Vec<String>,
    cwd: PathBuf,
    workspace_root: PathBuf,
    #[serde(default)]
    required_isolation: Option<IsolationLevel>,
    #[serde(default)]
    declared_mutation: bool,
}

#[derive(Debug, Serialize)]
struct ExecOutput {
    decision: String,
    reason: Option<String>,
    requested_isolation: IsolationLevel,
    supported_isolation: IsolationLevel,
    exit_code: Option<i32>,
    error: Option<String>,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("agent-exec error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let mut policy_path = None::<PathBuf>;
    let mut request_path = None::<PathBuf>;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--policy" => {
                let val = args
                    .next()
                    .ok_or_else(|| "missing value for --policy".to_string())?;
                policy_path = Some(PathBuf::from(val));
            }
            "--request" => {
                let val = args
                    .next()
                    .ok_or_else(|| "missing value for --request".to_string())?;
                request_path = Some(PathBuf::from(val));
            }
            _ => {
                return Err(format!(
                    "unknown argument: {arg}. usage: agent-exec --policy <policy.json> --request <request.json>"
                ));
            }
        }
    }

    let policy_path = policy_path.ok_or_else(|| "missing --policy".to_string())?;
    let request_path = request_path.ok_or_else(|| "missing --request".to_string())?;

    let policy = GatewayPolicy::load_json(&policy_path)
        .map_err(|e| format!("failed to load policy {}: {e}", policy_path.display()))?;

    let request_wire = load_request(&request_path)?;
    let required_isolation = request_wire
        .required_isolation
        .unwrap_or(policy.default_isolation);

    let request = ExecRequest::new(
        request_wire.program,
        request_wire.args,
        request_wire.cwd,
        required_isolation,
        request_wire.workspace_root,
    )
    .with_declared_mutation(request_wire.declared_mutation);

    let gateway = ExecGateway::with_policy(policy);
    let (event, result) = gateway.execute_status_with_event(&request);

    let output = match result {
        Ok(status) => {
            let code = status.code().unwrap_or(0);
            ExecOutput {
                decision: format!("{:?}", event.decision).to_lowercase(),
                reason: event.reason,
                requested_isolation: event.requested_isolation,
                supported_isolation: event.supported_isolation,
                exit_code: Some(code),
                error: None,
            }
        }
        Err(err) => ExecOutput {
            decision: format!("{:?}", event.decision).to_lowercase(),
            reason: event.reason,
            requested_isolation: event.requested_isolation,
            supported_isolation: event.supported_isolation,
            exit_code: None,
            error: Some(err.to_string()),
        },
    };

    println!(
        "{}",
        serde_json::to_string(&output).map_err(|e| format!("serialize output failed: {e}"))?
    );

    Ok(match output.exit_code {
        Some(0) => ExitCode::SUCCESS,
        Some(_) | None => ExitCode::FAILURE,
    })
}

fn load_request(path: &PathBuf) -> Result<ExecRequestWire, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("failed to read request {}: {e}", path.display()))?;
    serde_json::from_str(&content)
        .map_err(|e| format!("invalid request json {}: {e}", path.display()))
}
