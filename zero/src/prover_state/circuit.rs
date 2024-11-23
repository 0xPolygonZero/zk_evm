//! [`AllRecursiveCircuits`] dynamic circuit configuration.
use std::fmt::Display;

use evm_arithmetization::fixed_recursive_verifier::RecursionConfig;
use evm_arithmetization::recursive_verifier::MAX_DEGREE_BITS_TO_SUPPORT;
pub use evm_arithmetization::NUM_TABLES;
use evm_arithmetization::{AllRecursiveCircuits, AllStark};

/// All possible Plonky2 table circuits.
#[repr(usize)]
#[derive(Debug, Clone, Copy)]
pub enum Circuit {
    Arithmetic,
    BytePacking,
    Cpu,
    Keccak,
    KeccakSponge,
    Logic,
    Memory,
    MemoryBefore,
    MemoryAfter,
    #[cfg(feature = "cdk_erigon")]
    Poseidon,
}

impl Display for Circuit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Circuit {
    /// Get the default size for the circuit.
    pub const fn default_size(&self) -> usize {
        MAX_DEGREE_BITS_TO_SUPPORT
    }

    /// Get the environment variable key for the circuit.
    pub const fn as_env_key(&self) -> &'static str {
        match self {
            Circuit::Arithmetic => "ARITHMETIC_CIRCUIT_SIZE",
            Circuit::BytePacking => "BYTE_PACKING_CIRCUIT_SIZE",
            Circuit::Cpu => "CPU_CIRCUIT_SIZE",
            Circuit::Keccak => "KECCAK_CIRCUIT_SIZE",
            Circuit::KeccakSponge => "KECCAK_SPONGE_CIRCUIT_SIZE",
            Circuit::Logic => "LOGIC_CIRCUIT_SIZE",
            Circuit::Memory => "MEMORY_CIRCUIT_SIZE",
            Circuit::MemoryBefore => "MEMORY_BEFORE_CIRCUIT_SIZE",
            Circuit::MemoryAfter => "MEMORY_AFTER_CIRCUIT_SIZE",
            #[cfg(feature = "cdk_erigon")]
            Circuit::Poseidon => "POSEIDON_CIRCUIT_SIZE",
        }
    }

    /// Get the circuit name as a str literal.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Circuit::Arithmetic => "arithmetic",
            Circuit::BytePacking => "byte packing",
            Circuit::Cpu => "cpu",
            Circuit::Keccak => "keccak",
            Circuit::KeccakSponge => "keccak sponge",
            Circuit::Logic => "logic",
            Circuit::Memory => "memory",
            Circuit::MemoryBefore => "memory before",
            Circuit::MemoryAfter => "memory after",
            #[cfg(feature = "cdk_erigon")]
            Circuit::Poseidon => "poseidon",
        }
    }

    /// Get the circuit name as a short str literal.
    pub const fn as_short_str(&self) -> &'static str {
        match self {
            Circuit::Arithmetic => "a",
            Circuit::BytePacking => "bp",
            Circuit::Cpu => "c",
            Circuit::Keccak => "k",
            Circuit::KeccakSponge => "ks",
            Circuit::Logic => "l",
            Circuit::Memory => "m",
            Circuit::MemoryBefore => "m_b",
            Circuit::MemoryAfter => "m_a",
            #[cfg(feature = "cdk_erigon")]
            Circuit::Poseidon => "p",
        }
    }
}

impl From<usize> for Circuit {
    fn from(item: usize) -> Self {
        match item {
            0 => Circuit::Arithmetic,
            1 => Circuit::BytePacking,
            2 => Circuit::Cpu,
            3 => Circuit::Keccak,
            4 => Circuit::KeccakSponge,
            5 => Circuit::Logic,
            6 => Circuit::Memory,
            7 => Circuit::MemoryBefore,
            8 => Circuit::MemoryAfter,
            #[cfg(feature = "cdk_erigon")]
            9 => Circuit::Poseidon,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CircuitConfig {
    circuits: [usize; NUM_TABLES],
    pub use_test_config: bool,
}

impl std::ops::Index<usize> for CircuitConfig {
    type Output = usize;

    fn index(&self, index: usize) -> &Self::Output {
        &self.circuits[index]
    }
}

impl std::ops::Index<Circuit> for CircuitConfig {
    type Output = usize;

    fn index(&self, index: Circuit) -> &Self::Output {
        &self.circuits[index as usize]
    }
}

impl Default for CircuitConfig {
    fn default() -> Self {
        Self {
            circuits: [
                Circuit::Arithmetic.default_size(),
                Circuit::BytePacking.default_size(),
                Circuit::Cpu.default_size(),
                Circuit::Keccak.default_size(),
                Circuit::KeccakSponge.default_size(),
                Circuit::Logic.default_size(),
                Circuit::Memory.default_size(),
                Circuit::MemoryBefore.default_size(),
                Circuit::MemoryAfter.default_size(),
                #[cfg(feature = "cdk_erigon")]
                Circuit::Poseidon.default_size(),
            ],
            use_test_config: false,
        }
    }
}

impl CircuitConfig {
    /// Get all circuits specified in the config.
    pub fn iter(&self) -> std::slice::Iter<'_, usize> {
        self.circuits.iter()
    }

    /// Get all circuits specified in the config with their [`Circuit`] index.
    pub fn enumerate(&self) -> impl Iterator<Item = (Circuit, &usize)> {
        self.circuits
            .iter()
            .enumerate()
            .map(|(index, deg)| (index.into(), deg))
    }

    /// Set size of the given [`Circuit`].
    pub fn set_circuit_size(&mut self, key: Circuit, size: usize) {
        self.circuits[key as usize] = size;
    }

    /// Get all circuits specified in the config.
    pub const fn as_degree_bits(&self) -> &[usize; NUM_TABLES] {
        &self.circuits
    }

    /// Get a unique string representation of the config.
    pub fn get_configuration_digest(&self) -> String {
        self.enumerate()
            .map(|(circuit, deg)| format!("{}-{}", circuit.as_short_str(), deg))
            .fold(String::new(), |mut acc, s| {
                if !acc.is_empty() {
                    acc.push('_');
                }
                acc.push_str(&s);
                acc
            })
    }

    /// Build the circuits from the current config.
    pub fn as_all_recursive_circuits(&self) -> AllRecursiveCircuits {
        if self.use_test_config {
            AllRecursiveCircuits::new(&AllStark::default(), RecursionConfig::test_config())
        } else {
            AllRecursiveCircuits::new(&AllStark::default(), RecursionConfig::default())
        }
    }
}

impl IntoIterator for CircuitConfig {
    type Item = usize;
    type IntoIter = std::array::IntoIter<Self::Item, NUM_TABLES>;

    fn into_iter(self) -> Self::IntoIter {
        self.circuits.into_iter()
    }
}
