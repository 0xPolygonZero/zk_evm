//! This module defines the `VerifierState`, that contains the necessary data to
//! handle succinct block proofs verification.

use log::info;

use crate::prover_state::ProverStateBuilder;
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
        let ProverState { state } = self.build(false);
        info!("Finished initializing Plonky2 aggregation verifier state!");

        VerifierState {
            state: state.final_verifier_data(),
        }
    }
}

/// Extracts the verifier state from the entire prover state.
impl From<ProverState> for VerifierState {
    fn from(prover_state: ProverState) -> Self {
        VerifierState {
            state: prover_state.state.final_verifier_data(),
        }
    }
}
