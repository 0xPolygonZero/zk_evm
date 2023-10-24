use std::io::Read;

use anyhow::Result;
use paladin::runtime::Runtime;
use tracing::info;

use crate::prover_input::ProverInput;

/// The main function for the stdio mode.
pub(crate) async fn stdio_main(runtime: Runtime) -> Result<()> {
    let mut buffer = String::new();
    std::io::stdin().read_to_string(&mut buffer)?;

    let input: ProverInput = serde_json::from_str(&buffer)?;
    let proof = input.prove(&runtime).await?;
    info!("Successfully proved {:#?}", proof);

    Ok(())
}
