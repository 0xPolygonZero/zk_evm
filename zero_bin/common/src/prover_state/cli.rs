//! CLI arguments for constructing a [`CircuitConfig`], which can be used to
//! construct table circuits.
use clap::Args;

use super::{
    circuit::{Circuit, CircuitConfig, CircuitSize},
    CircuitPersistence, ProverStateConfig,
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

/// Macro for generating the [`CliCircuitConfig`] struct.
macro_rules! gen_prover_state_config {
    ($($name:ident: $circuit:expr),*) => {
        #[derive(Args, Debug)]
        pub struct CliProverStateConfig {
            #[clap(long, help_heading = HEADING, default_value_t = CircuitPersistence::Disk)]
            pub persistence: CircuitPersistence,

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

    pub fn into_prover_state_config(self) -> ProverStateConfig {
        ProverStateConfig {
            persistence: self.persistence,
            circuit_config: self.into_circuit_config(),
        }
    }
}

impl From<CliProverStateConfig> for ProverStateConfig {
    fn from(item: CliProverStateConfig) -> Self {
        item.into_prover_state_config()
    }
}
