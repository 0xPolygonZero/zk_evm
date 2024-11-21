use std::process::{Command, Stdio};

use anyhow::Result;
use anyhow::{ensure, Context as _};
use serde::Deserialize;

#[derive(Deserialize)]
struct Outdated<'a> {
    crate_name: &'a str,
    dependencies: Vec<Dependency<'a>>,
}

#[derive(Deserialize)]
struct Dependency<'a> {
    name: &'a str,
    project: &'a str,
    latest: &'a str,
}

pub fn list_outdated_deps() -> Result<()> {
    let output = Command::new("cargo")
        .args(["outdated", "--root-deps-only", "--format=json"])
        .stderr(Stdio::inherit())
        .stdout(Stdio::piped())
        .output()
        .context("couldn't exec `cargo`")?;
    ensure!(
        output.status.success(),
        "command failed with {}",
        output.status
    );

    let outdated_items = serde_json::Deserializer::from_slice(&output.stdout)
        .into_iter::<Outdated<'_>>()
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse output from `cargo outdated`")?;
    for Outdated {
        crate_name,
        dependencies,
    } in outdated_items
    {
        for Dependency {
            name,
            project,
            latest,
        } in dependencies
        {
            // https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/workflow-commands-for-github-actions#setting-a-warning-message
            println!("::warning title=outdated-dependency::dependency {name} of crate {crate_name} is at version {project}, but the latest is {latest}")
        }
    }

    Ok(())
}
