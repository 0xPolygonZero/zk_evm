//! This module defines the `VerifierState`, that contains the necessary data to
//! handle succinct block proofs verification.

use core::borrow::Borrow;

use log::info;
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;

use crate::proof_gen::ProofGenResult;
use crate::prover_state::ProverStateBuilder;
use crate::types::PlonkyProofIntern;
use crate::{prover_state::ProverState, types::VerifierData};

/// Plonky2 verifier state.
///
/// The default generation requires generating all the prover data before
/// extracting the verifier-related data, which can take a long time and require
/// a large amount of memory.
pub struct VerifierState {
    /// The verification circuit data associated to the block proof layer of the
    /// plonky2 prover state.
    pub state: VerifierData,
}

/// Builder for the verifier state.
/// This is essentially the same as the [`ProverStateBuilder`], in that we need
/// to first generate the entire prover state before extracting the verifier
/// data.
pub type VerifierStateBuilder = ProverStateBuilder;

impl VerifierStateBuilder {
    /// Instantiate the verifier state from the builder. Note that this is a
    /// very expensive call!
    pub fn build_verifier(self) -> VerifierState {
        info!("Initializing Plonky2 aggregation verifier state (This may take a while)...");
        let ProverState { state } = self.build();
        info!("Finished initializing Plonky2 aggregation verifier state!");

        VerifierState {
            state: state.final_verifier_data(),
        }
    }
}

/// Extracts the verifier state from the entire prover state.
impl<T: Borrow<ProverState>> From<T> for VerifierState {
    fn from(prover_state: T) -> Self {
        VerifierState {
            state: prover_state.borrow().state.final_verifier_data(),
        }
    }
}

impl VerifierState {
    /// Verifies a `block_proof`.
    pub fn verify(&self, block_proof: &PlonkyProofIntern) -> ProofGenResult<()> {
        // Proof verification
        self.state
            .verify(block_proof.clone())
            .map_err(|err| err.to_string())?;

        // Verifier data verification
        check_cyclic_proof_verifier_data(
            block_proof,
            &self.state.verifier_only,
            &self.state.common,
        )
        .map_err(|err| err.to_string())?;

        Ok(())
    }
}
