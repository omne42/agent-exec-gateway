use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::audit::ExecEvent;
use crate::error::ExecError;

#[derive(Debug, Clone)]
pub struct AuditLogger {
    path: PathBuf,
}

impl AuditLogger {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn write_record(&self, event: &ExecEvent, result: &Result<(), &ExecError>) {
        let record = AuditRecord::new(event, result);
        let line = match serde_json::to_string(&record) {
            Ok(data) => data,
            Err(_) => return,
        };

        let mut file = match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(file) => file,
            Err(_) => return,
        };

        let _ = writeln!(file, "{line}");
    }
}

#[derive(Debug, Serialize)]
struct AuditRecord {
    ts_unix_ms: u128,
    event: ExecEvent,
    result: AuditResult,
}

impl AuditRecord {
    fn new(event: &ExecEvent, result: &Result<(), &ExecError>) -> Self {
        let ts_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);

        let result = match result {
            Ok(()) => AuditResult {
                status: "ok",
                error: None,
            },
            Err(err) => AuditResult {
                status: "error",
                error: Some(err.to_string()),
            },
        };

        Self {
            ts_unix_ms,
            event: event.clone(),
            result,
        }
    }
}

#[derive(Debug, Serialize)]
struct AuditResult {
    status: &'static str,
    error: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;
    use crate::audit::{ExecDecision, ExecEvent};
    use crate::types::IsolationLevel;

    #[test]
    fn writes_jsonl_record() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(&path);

        let event = ExecEvent {
            decision: ExecDecision::Run,
            requested_isolation: IsolationLevel::BestEffort,
            supported_isolation: IsolationLevel::BestEffort,
            program: "echo".into(),
            cwd: ".".into(),
            workspace_root: ".".into(),
            declared_mutation: false,
            reason: None,
        };

        logger.write_record(&event, &Ok(()));

        let content = fs::read_to_string(path).expect("read audit");
        assert!(content.contains("\"status\":\"ok\""));
        assert!(content.contains("\"decision\":\"run\""));
        assert!(content.contains("\"program\":\"echo\""));
    }
}
