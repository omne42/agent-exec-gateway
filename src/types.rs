use std::ffi::OsString;
use std::path::PathBuf;

pub use policy_meta::ExecutionIsolation as IsolationLevel;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecRequest {
    pub program: OsString,
    pub args: Vec<OsString>,
    pub cwd: PathBuf,
    pub required_isolation: IsolationLevel,
    pub workspace_root: PathBuf,
    pub declared_mutation: bool,
}

impl ExecRequest {
    pub fn new<I, S>(
        program: impl Into<OsString>,
        args: I,
        cwd: impl Into<PathBuf>,
        required_isolation: IsolationLevel,
        workspace_root: impl Into<PathBuf>,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
            cwd: cwd.into(),
            required_isolation,
            workspace_root: workspace_root.into(),
            declared_mutation: false,
        }
    }

    pub fn with_declared_mutation(mut self, declared_mutation: bool) -> Self {
        self.declared_mutation = declared_mutation;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_new_accepts_string_like_args() {
        let request = ExecRequest::new(
            "echo",
            vec!["hello", "world"],
            ".",
            IsolationLevel::None,
            ".",
        );

        assert_eq!(request.program, OsString::from("echo"));
        assert_eq!(
            request.args,
            vec![OsString::from("hello"), OsString::from("world")]
        );
        assert!(!request.declared_mutation);
    }

    #[cfg(unix)]
    #[test]
    fn request_keeps_non_utf8_arguments_on_unix() {
        use std::os::unix::ffi::OsStringExt;

        let non_utf8 = OsString::from_vec(vec![0x66, 0x6f, 0x80]);
        let request = ExecRequest::new(
            OsString::from("tool"),
            vec![non_utf8.clone()],
            ".",
            IsolationLevel::None,
            ".",
        );

        assert_eq!(request.args, vec![non_utf8]);
    }

    #[test]
    fn request_can_be_marked_as_mutating() {
        let request = ExecRequest::new("echo", vec!["hi"], ".", IsolationLevel::None, ".")
            .with_declared_mutation(true);
        assert!(request.declared_mutation);
    }
}
