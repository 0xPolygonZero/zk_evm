//! This module defines the `ProverState`, that contains all pre-processed
//! circuits necessary to handle arbitrary transaction proving and proof
//! aggregation to generate succinct block proofs attesting validity of an
//! entire EVM-based chain.

use std::ops::Range;

use log::info;
use paste::paste;
use plonky2_evm::{all_stark::AllStark, config::StarkConfig};

use crate::constants::*;
use crate::types::AllRecursiveCircuits;

/// Plonky2 proving state. Note that this is generally going to be massive in
/// terms of memory and has a long spin-up time,
pub struct ProverState {
    /// The set of pre-processed circuits to recursively prove transactions.
    pub state: AllRecursiveCircuits,
}

/// Builder for the prover state.
#[derive(Debug)]
pub struct ProverStateBuilder {
    pub(crate) arithmetic_circuit_size: Range<usize>,
    pub(crate) byte_packing_circuit_size: Range<usize>,
    pub(crate) cpu_circuit_size: Range<usize>,
    pub(crate) keccak_circuit_size: Range<usize>,
    pub(crate) keccak_sponge_circuit_size: Range<usize>,
    pub(crate) logic_circuit_size: Range<usize>,
    pub(crate) memory_circuit_size: Range<usize>,
}

impl Default for ProverStateBuilder {
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

impl ProverStateBuilder {
    define_set_circuit_size_method!(arithmetic);
    define_set_circuit_size_method!(byte_packing);
    define_set_circuit_size_method!(cpu);
    define_set_circuit_size_method!(keccak);
    define_set_circuit_size_method!(keccak_sponge);
    define_set_circuit_size_method!(logic);
    define_set_circuit_size_method!(memory);

    // TODO: Consider adding async version?
    /// Instantiate the prover state from the builder. Note that this is a very
    /// expensive call!
    pub fn build(self, verbose: bool) -> ProverState {
        if verbose {
            info!("Initializing Plonky2 aggregation prover state (This may take a while)...");
        }

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

        if verbose {
            info!("Finished initializing Plonky2 aggregation prover state!");
        }

        ProverState { state }
    }
}
