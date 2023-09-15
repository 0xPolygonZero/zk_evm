use std::ops::Range;

use log::info;
use paste::paste;
use plonky2_evm::{all_stark::AllStark, config::StarkConfig};

use crate::types::AllRecursiveCircuits;

/// Plonky2 proving state. Note that is is generally going to be massive in
/// terms of memory and has a long spin-up time,
pub struct ProverState {
    pub(crate) state: AllRecursiveCircuits,
}

/// Builder for the prover state.
#[derive(Debug)]
pub struct ProverStateBuilder {
    arithmetic_circuit_size: Range<usize>,
    byte_packing_circuit_size: Range<usize>,
    cpu_circuit_size: Range<usize>,
    keccak_circuit_size: Range<usize>,
    keccak_sponge_circuit_size: Range<usize>,
    logic_circuit_size: Range<usize>,
    memory_circuit_size: Range<usize>,
}

impl Default for ProverStateBuilder {
    fn default() -> Self {
        Self {
            arithmetic_circuit_size: 9..22,
            byte_packing_circuit_size: 9..22,
            cpu_circuit_size: 9..22,
            keccak_circuit_size: 9..22,
            keccak_sponge_circuit_size: 9..22,
            logic_circuit_size: 9..22,
            memory_circuit_size: 9..22,
        }
    }
}

macro_rules! define_set_circuit_size_method {
    ($name:ident) => {
        paste! {
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
    pub fn build(self) -> ProverState {
        info!("Initializing Plonky2 aggregation prover state (This may take a while)...");

        // ... Yeah I don't understand the mysterious ranges either :)
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

        info!("Finished initializing Plonky2 aggregation prover state!");

        ProverState { state }
    }
}
