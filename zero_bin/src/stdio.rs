use std::io::Read;

use anyhow::Result;
use plonky_block_proof_gen::prover_state::ProverState;
use tracing::info;

use crate::prover_input::ProverInput;

/// The main function for the stdio mode.
pub(crate) fn stdio_main(p_state: ProverState) -> Result<()> {
    let mut buffer = String::new();
    std::io::stdin().read_to_string(&mut buffer)?;

    let input: ProverInput = serde_json::from_str(&buffer)?;
    let proof = input.prove(&p_state)?;
    info!("Successfully proved {:#?}", proof);

    Ok(())
}
