//! This module defines the `VerifierState`, that contains the necessary data to
//! handle succinct block proofs verification.

use std::ops::Range;

use log::info;
use paste::paste;
use plonky2_evm::{all_stark::AllStark, config::StarkConfig};

use crate::constants::*;
use crate::{
    prover_state::ProverState,
    types::{AllRecursiveCircuits, VerifierData},
};

/// Plonky2 verifier state.
///
/// The default generation requires generating all the verifier data before
/// extracting the verifier-related data, which can take a long time and require
/// a large amount of memory.
pub struct VerifierState {
    ///
    pub state: VerifierData,
}

/// Builder for the verifier state.
#[derive(Debug)]
pub struct VerifierStateBuilder {
    arithmetic_circuit_size: Range<usize>,
    byte_packing_circuit_size: Range<usize>,
    cpu_circuit_size: Range<usize>,
    keccak_circuit_size: Range<usize>,
    keccak_sponge_circuit_size: Range<usize>,
    logic_circuit_size: Range<usize>,
    memory_circuit_size: Range<usize>,
}

impl Default for VerifierStateBuilder {
    fn default() -> Self {
        // The default ranges are somewhat arbitrary, but should be enough for testing
        // purposes against most transactions.
        // Some heavy contract deployments may require bumping these ranges though.
        Self {
            arithmetic_circuit_size: DEFAULT_ARITHMETIC_RANGE,
            byte_packing_circuit_size: DEFAULT_BYTE_PACKING_RANGE,
            cpu_circuit_size: DEFAULT_CPU_RANGE,
            keccak_circuit_size: DEFAULT_KECCAK_RANGE,
            keccak_sponge_circuit_size: DEFAULT_KECCAK_SPONGE_RANGE,
            logic_circuit_size: DEFAULT_LOGIC_RANGE,
            memory_circuit_size: DEFAULT_MEMORY_RANGE,
        }
    }
}

macro_rules! define_set_circuit_size_method {
    ($name:ident) => {
        paste! {
            /// Specifies a range of degrees to be supported for this STARK
            /// table's associated recursive circuits.
            pub fn [<set_ $name _circuit_size>](mut self, size: Range<usize>) -> Self {
                self.[<$name _circuit_size>] = size;
                self
            }
        }
    };
}

impl VerifierStateBuilder {
    define_set_circuit_size_method!(arithmetic);
    define_set_circuit_size_method!(byte_packing);
    define_set_circuit_size_method!(cpu);
    define_set_circuit_size_method!(keccak);
    define_set_circuit_size_method!(keccak_sponge);
    define_set_circuit_size_method!(logic);
    define_set_circuit_size_method!(memory);

    // TODO: Consider adding async version?
    /// Instantiate the verifier state from the builder. Note that this is a
    /// very expensive call!
    pub fn build(self) -> VerifierState {
        info!("Initializing Plonky2 aggregation verifier state (This may take a while)...");

        let state = AllRecursiveCircuits::new(
            &AllStark::default(),
            &[
                self.arithmetic_circuit_size,
                self.byte_packing_circuit_size,
                self.cpu_circuit_size,
                self.keccak_circuit_size,
                self.keccak_sponge_circuit_size,
                self.logic_circuit_size,
                self.memory_circuit_size,
            ],
            &StarkConfig::standard_fast_config(),
        );

        info!("Finished initializing Plonky2 aggregation verifier state!");

        VerifierState { state }
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
