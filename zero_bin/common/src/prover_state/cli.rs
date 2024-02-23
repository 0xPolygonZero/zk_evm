//! CLI arguments for constructing a [`CircuitConfig`], which can be used to
//! construct table circuits.
use std::fmt::Display;

use clap::{Args, ValueEnum};

use super::{
    circuit::{Circuit, CircuitConfig, CircuitSize},
    ProverStateManager, TableLoadStrategy,
};

/// The help heading for the circuit arguments.
///
/// This groups the circuit arguments together in the help message.
const HEADING: &str = "Table circuit sizes";
/// The clap value name for the circuit argument.
const VALUE_NAME: &str = "CIRCUIT_BIT_RANGE";

/// Get the description for the circuit argument.
///
/// Displayed in the help message.
fn circuit_arg_desc(circuit_name: &str) -> String {
    format!("The min/max size for the {circuit_name} table circuit.")
}

/// Specifies whether to persist the processed circuits.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CircuitPersistence {
    /// Do not persist the processed circuits.
    None,
    /// Persist the processed circuits to disk.
    Disk,
}

impl CircuitPersistence {
    pub fn with_load_strategy(self, load_strategy: TableLoadStrategy) -> super::CircuitPersistence {
        match self {
            CircuitPersistence::None => super::CircuitPersistence::None,
            CircuitPersistence::Disk => super::CircuitPersistence::Disk(load_strategy),
        }
    }
}

impl Display for CircuitPersistence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitPersistence::None => write!(f, "none"),
            CircuitPersistence::Disk => write!(f, "disk"),
        }
    }
}

/// Macro for generating the [`CliCircuitConfig`] struct.
macro_rules! gen_prover_state_config {
    ($($name:ident: $circuit:expr),*) => {
        #[derive(Args, Debug)]
        pub struct CliProverStateConfig {
            #[clap(long, help_heading = HEADING, default_value_t = CircuitPersistence::Disk)]
            pub persistence: CircuitPersistence,
            #[clap(long, help_heading = HEADING, default_value_t = TableLoadStrategy::OnDemand)]
            pub load_strategy: TableLoadStrategy,

            $(
                #[clap(
                    long,
                    value_name = VALUE_NAME,
                    help_heading = HEADING,
                    env = $circuit.as_env_key(),
                    help = circuit_arg_desc($circuit.as_str()),
                )]
                pub $name: Option<CircuitSize>,
            )*
        }
    };
}

gen_prover_state_config!(
    arithmetic: Circuit::Arithmetic,
    byte_packing: Circuit::BytePacking,
    cpu: Circuit::Cpu,
    keccak: Circuit::Keccak,
    keccak_sponge: Circuit::KeccakSponge,
    logic: Circuit::Logic,
    memory: Circuit::Memory
);

impl CliProverStateConfig {
    pub fn into_circuit_config(self) -> CircuitConfig {
        let mut config = CircuitConfig::default();

        [
            (Circuit::Arithmetic, self.arithmetic),
            (Circuit::BytePacking, self.byte_packing),
            (Circuit::Cpu, self.cpu),
            (Circuit::Keccak, self.keccak),
            (Circuit::KeccakSponge, self.keccak_sponge),
            (Circuit::Logic, self.logic),
            (Circuit::Memory, self.memory),
        ]
        .into_iter()
        .filter_map(|(circuit, range)| range.map(|range| (circuit, range)))
        .for_each(|(circuit, range)| config.set_circuit_size(circuit, range));

        config
    }

    pub fn into_prover_state_manager(self) -> ProverStateManager {
        ProverStateManager {
            persistence: self.persistence.with_load_strategy(self.load_strategy),
            circuit_config: self.into_circuit_config(),
        }
    }
}

impl From<CliProverStateConfig> for ProverStateManager {
    fn from(config: CliProverStateConfig) -> Self {
        config.into_prover_state_manager()
    }
}
