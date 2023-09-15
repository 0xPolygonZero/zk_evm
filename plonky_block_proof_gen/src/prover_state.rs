use std::ops::Range;

use plonky2_evm::{all_stark::AllStark, config::StarkConfig};

use crate::types::AllRecursiveCircuits;

pub struct ProverState {
    pub(crate) state: AllRecursiveCircuits,
}

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

impl ProverStateBuilder {
    pub fn build(self) -> ProverState {
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

        ProverState { state }
    }
}
