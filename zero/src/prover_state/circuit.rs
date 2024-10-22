//! [`AllRecursiveCircuits`] dynamic circuit configuration.
use std::{
    fmt::Display,
    ops::{Deref, Range},
    str::FromStr,
};

use evm_arithmetization::testing_utils::{
    TEST_RECURSION_CONFIG, TEST_STARK_CONFIG, TEST_THRESHOLD_DEGREE_BITS,
};
pub use evm_arithmetization::NUM_TABLES;
use evm_arithmetization::{AllRecursiveCircuits, AllStark, StarkConfig};

use crate::parsing::{parse_range_exclusive, RangeParseError};

/// New type wrapper for [`Range`] that implements [`FromStr`] and [`Display`].
///
/// Useful for using in clap arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitSize(pub Range<usize>);

impl Deref for CircuitSize {
    type Target = Range<usize>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for CircuitSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}..{}", self.start, self.end)
    }
}

impl From<Range<usize>> for CircuitSize {
    fn from(item: Range<usize>) -> Self {
        Self(item)
    }
}

impl From<CircuitSize> for Range<usize> {
    fn from(item: CircuitSize) -> Self {
        item.0
    }
}

impl FromStr for CircuitSize {
    type Err = RangeParseError<usize>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(CircuitSize(parse_range_exclusive(s)?))
    }
}

/// All possible plonky2 table circuits.
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
    pub const fn default_size(&self) -> Range<usize> {
        match self {
            Circuit::Arithmetic => 16..23,
            Circuit::BytePacking => 9..21,
            Circuit::Cpu => 12..25,
            Circuit::Keccak => 14..20,
            Circuit::KeccakSponge => 9..15,
            Circuit::Logic => 12..18,
            Circuit::Memory => 17..28,
            Circuit::MemoryBefore => 7..23,
            Circuit::MemoryAfter => 7..27,
            #[cfg(feature = "cdk_erigon")]
            Circuit::Poseidon => 4..22,
        }
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
    circuits: [Range<usize>; NUM_TABLES],
    pub use_test_config: bool,
}

impl std::ops::Index<usize> for CircuitConfig {
    type Output = Range<usize>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.circuits[index]
    }
}

impl std::ops::Index<Circuit> for CircuitConfig {
    type Output = Range<usize>;

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
    pub fn iter(&self) -> std::slice::Iter<'_, Range<usize>> {
        self.circuits.iter()
    }

    /// Get all circuits specified in the config with their [`Circuit`] index.
    pub fn enumerate(&self) -> impl Iterator<Item = (Circuit, &Range<usize>)> {
        self.circuits
            .iter()
            .enumerate()
            .map(|(index, range)| (index.into(), range))
    }

    /// Set the size of a the given [`Circuit`].
    pub fn set_circuit_size<T: Into<Range<usize>>>(&mut self, key: Circuit, size: T) {
        self.circuits[key as usize] = size.into();
    }

    /// Get all circuits specified in the config.
    pub const fn as_degree_bits_ranges(&self) -> &[Range<usize>; NUM_TABLES] {
        &self.circuits
    }

    /// Get a unique string representation of the config.
    pub fn get_configuration_digest(&self) -> String {
        self.enumerate()
            .map(|(circuit, range)| {
                format!("{}_{}-{}", circuit.as_short_str(), range.start, range.end)
            })
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
            AllRecursiveCircuits::new(
                &AllStark::default(),
                self.as_degree_bits_ranges(),
                &TEST_STARK_CONFIG,
                Some(&TEST_RECURSION_CONFIG),
                Some(&TEST_RECURSION_CONFIG),
                Some(TEST_THRESHOLD_DEGREE_BITS),
            )
        } else {
            AllRecursiveCircuits::new(
                &AllStark::default(),
                self.as_degree_bits_ranges(),
                &StarkConfig::standard_fast_config(),
                None,
                None,
                None,
            )
        }
    }
}

impl IntoIterator for CircuitConfig {
    type Item = Range<usize>;
    type IntoIter = std::array::IntoIter<Self::Item, NUM_TABLES>;

    fn into_iter(self) -> Self::IntoIter {
        self.circuits.into_iter()
    }
}

impl<'a> IntoIterator for &'a CircuitConfig {
    type Item = &'a Range<usize>;
    type IntoIter = std::slice::Iter<'a, Range<usize>>;

    fn into_iter(self) -> Self::IntoIter {
        self.circuits.iter()
    }
}
