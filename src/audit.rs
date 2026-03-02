use std::ffi::OsString;
use std::path::PathBuf;

use serde::Serialize;
use serde::ser::Serializer;

use crate::types::IsolationLevel;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecDecision {
    Run,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExecEvent {
    pub decision: ExecDecision,
    pub requested_isolation: IsolationLevel,
    pub supported_isolation: IsolationLevel,
    #[serde(serialize_with = "serialize_os_string_lossy")]
    pub program: OsString,
    pub cwd: PathBuf,
    pub workspace_root: PathBuf,
    pub declared_mutation: bool,
    pub reason: Option<String>,
}

fn serialize_os_string_lossy<S>(value: &OsString, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&value.to_string_lossy())
}
