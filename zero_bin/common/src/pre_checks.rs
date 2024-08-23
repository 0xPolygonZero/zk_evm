use proof_gen::proof_types::GeneratedBlockProof;

pub fn check_previous_proof_and_checkpoint(
    checkpoint_block_number: u64,
    previous_proof: &Option<GeneratedBlockProof>,
    start: u64,
) -> anyhow::Result<()> {
    if let Some(proof) = previous_proof {
        if proof.b_height + 1 != start {
            return Err(anyhow::Error::msg(format!(
                "Previous proof block height {} does not match current starting block height {}",
                proof.b_height, start,
            )));
        }
        if checkpoint_block_number >= start {
            return Err(anyhow::Error::msg(format!(
                "Previous proof present. Found checkpoint block number {} whereas range start is {}",
                checkpoint_block_number, start
            )));
        }
    } else if checkpoint_block_number != start - 1 {
        return Err(anyhow::Error::msg(format!(
            "Previous proof not found. Found checkpoint block number {} whereas range start is {}",
            checkpoint_block_number, start
        )));
    }

    Ok(())
}
