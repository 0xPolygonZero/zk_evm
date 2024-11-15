use std::{
    fs::File,
    path::PathBuf,
    process::{Command, Stdio},
};

use anyhow::{Context as _, Result};

pub struct Runner {
    cmd: String,
    args: Vec<String>,
    stdout: Stdio,
    stderr: Stdio,
}

impl Runner {
    /// Create a new runner with the given command.
    pub fn new(cmd: impl Into<String>) -> Self {
        Self {
            cmd: cmd.into(),
            args: vec![],
            stdout: Stdio::piped(),
            stderr: Stdio::piped(),
        }
    }

    /// Add arguments to the command.
    pub fn args(mut self, args: &[&str]) -> Self {
        self.args.extend(args.iter().map(|s| s.to_string()));
        self
    }

    /// Create the file specified by `output_filepath` and set it as the stdout
    /// and stderr of the command.
    pub fn out(mut self, output_filepath: impl Into<PathBuf>) -> Result<Self> {
        let out = File::create(output_filepath.into())?;
        let err = out.try_clone()?;
        self.stdout = Stdio::from(out);
        self.stderr = Stdio::from(err);
        Ok(self)
    }

    /// Run the command.
    pub fn run(self) -> Result<()> {
        let output = Command::new(&self.cmd)
            .args(&self.args)
            .stdout(self.stdout)
            .stderr(self.stderr)
            .output()
            .context(format!("couldn't exec `{}`", &self.cmd))?;
        todo!()
    }
}
