//! Global prover state management and utilities.
//!
//! This module provides the following:
//! - [`Circuit`] and [`CircuitConfig`] which can be used to dynamically
//!   construct [`evm_arithmetization::fixed_recursive_verifier::AllRecursiveCircuits`]
//!   from the specified circuit sizes.
//! - Command line arguments for constructing a [`CircuitConfig`].
//!     - Provides default values for the circuit sizes.
//!     - Allows the circuit sizes to be specified via environment variables.
//! - Persistence utilities for saving and loading
//!   [`evm_arithmetization::fixed_recursive_verifier::AllRecursiveCircuits`].
//! - Global prover state management via the [`P_STATE`] static and the
//!   [`set_prover_state_from_config`] function.
use std::{fmt::Display, sync::OnceLock};

use clap::ValueEnum;
use evm_arithmetization::{
    proof::AllProof, prover::prove, AllStark, GenerationInputs, StarkConfig,
};
use plonky2::{
    field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    util::timing::TimingTree,
};
use proof_gen::{proof_types::GeneratedTxnProof, prover_state::ProverState, VerifierState};
use tracing::info;

use self::circuit::{CircuitConfig, NUM_TABLES};
use crate::prover_state::persistence::{
    BaseProverResource, DiskResource, MonolithicProverResource, RecursiveCircuitResource,
    VerifierResource,
};

pub mod circuit;
pub mod cli;
pub mod persistence;

pub(crate) type Config = PoseidonGoldilocksConfig;
pub(crate) type Field = GoldilocksField;
pub(crate) const SIZE: usize = 2;

pub(crate) type RecursiveCircuitsForTableSize =
    evm_arithmetization::fixed_recursive_verifier::RecursiveCircuitsForTableSize<
        Field,
        Config,
        SIZE,
    >;

/// The global prover state.
///
/// It is specified as a `OnceLock` for the following reasons:
/// - It is initialized once at start-up and never changed.
/// - It is accessible from multiple threads (particularly important when
///   running the leader in in-memory mode).
/// - This scheme works for both a cluster and a single machine. In particular,
///   whether imported from a worker node or a thread in the leader node
///   (in-memory mode), the prover state is initialized only once.
static P_STATE: OnceLock<ProverState> = OnceLock::new();

/// The global prover state manager.
///
/// Unlike the prover state, the prover state manager houses configuration and
/// persistence information. This allows it to differentiate between the
/// different transaction proof generation strategies. As such, it is generally
/// only necessary when generating transaction proofs.
///
/// It's specified as a `OnceLock` for the same reasons as the prover state.
static MANAGER: OnceLock<ProverStateManager> = OnceLock::new();

pub fn p_state() -> &'static ProverState {
    P_STATE.get().expect("Prover state is not initialized")
}

pub fn p_manager() -> &'static ProverStateManager {
    MANAGER
        .get()
        .expect("Prover state manager is not initialized")
}

/// Specifies how to load the table circuits.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum TableLoadStrategy {
    #[default]
    /// Load the circuit tables as needed for shrinking STARK proofs.
    ///
    /// - Generate a STARK proof.
    /// - Compute the degree bits.
    /// - Load the necessary table circuits.
    OnDemand,
    /// Load all the table circuits into a monolithic bundle.
    Monolithic,
}

impl Display for TableLoadStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TableLoadStrategy::OnDemand => write!(f, "on-demand"),
            TableLoadStrategy::Monolithic => write!(f, "monolithic"),
        }
    }
}

/// Specifies whether to persist the processed circuits.
#[derive(Debug, Clone, Copy)]
pub enum CircuitPersistence {
    /// Do not persist the processed circuits.
    None,
    /// Persist the processed circuits to disk.
    Disk(TableLoadStrategy),
}

impl Default for CircuitPersistence {
    fn default() -> Self {
        CircuitPersistence::Disk(TableLoadStrategy::default())
    }
}

/// Product of [`CircuitConfig`] and [`CircuitPersistence`].
///
/// Provides helper utilities for interacting with the prover state in
/// accordance with the specified configuration and persistence strategy.
#[derive(Default, Debug, Clone)]
pub struct ProverStateManager {
    pub circuit_config: CircuitConfig,
    pub persistence: CircuitPersistence,
}

impl ProverStateManager {
    pub fn with_load_strategy(self, load_strategy: TableLoadStrategy) -> Self {
        match self.persistence {
            CircuitPersistence::None => self,
            CircuitPersistence::Disk(_) => Self {
                circuit_config: self.circuit_config,
                persistence: CircuitPersistence::Disk(load_strategy),
            },
        }
    }

    /// Load the table circuits necessary to shrink the STARK proof.
    ///
    /// [`AllProof`] provides the necessary degree bits for each circuit via the
    /// [`AllProof::degree_bits`] method.
    /// Using this information, for each circuit, a tuple is returned,
    /// containing:
    /// 1. The loaded table circuit at the specified size.
    /// 2. An offset indicating the position of the specified size within the
    ///    configured range used when pre-generating the circuits.
    fn load_table_circuits(
        &self,
        config: &StarkConfig,
        all_proof: &AllProof<Field, Config, SIZE>,
    ) -> anyhow::Result<[(RecursiveCircuitsForTableSize, u8); NUM_TABLES]> {
        let degrees = all_proof.degree_bits(config);

        /// Given a recursive circuit index (e.g., Arithmetic / 0), return a
        /// tuple containing the loaded table at the specified size and
        /// its offset relative to the configured range used to pre-process the
        /// circuits.
        macro_rules! circuit {
            ($circuit_index:expr) => {
                (
                    RecursiveCircuitResource::get(&(
                        $circuit_index.into(),
                        degrees[$circuit_index],
                    ))
                    .map_err(|e| {
                        let circuit: $crate::prover_state::circuit::Circuit = $circuit_index.into();
                        let size = degrees[$circuit_index];
                        anyhow::Error::from(e).context(format!(
                            "Attempting to load circuit: {circuit:?} at size: {size}"
                        ))
                    })?,
                    (degrees[$circuit_index] - self.circuit_config[$circuit_index].start) as u8,
                )
            };
        }

        Ok([
            circuit!(0),
            circuit!(1),
            circuit!(2),
            circuit!(3),
            circuit!(4),
            circuit!(5),
            circuit!(6),
        ])
    }

    /// Generate a transaction proof using the specified input, loading the
    /// circuit tables as needed to shrink the individual STARK proofs, and
    /// finally aggregating them to a final transaction proof.
    fn txn_proof_on_demand(&self, input: GenerationInputs) -> anyhow::Result<GeneratedTxnProof> {
        let config = StarkConfig::standard_fast_config();
        let all_stark = AllStark::default();
        let all_proof = prove(&all_stark, &config, input, &mut TimingTree::default(), None)?;

        let table_circuits = self.load_table_circuits(&config, &all_proof)?;

        let (intern, p_vals) =
            p_state()
                .state
                .prove_root_after_initial_stark(all_proof, &table_circuits, None)?;

        Ok(GeneratedTxnProof { intern, p_vals })
    }

    /// Generate a transaction proof using the specified input on the monolithic
    /// circuit.
    fn txn_proof_monolithic(&self, input: GenerationInputs) -> anyhow::Result<GeneratedTxnProof> {
        let (intern, p_vals) = p_state().state.prove_root(
            &AllStark::default(),
            &StarkConfig::standard_fast_config(),
            input,
            &mut TimingTree::default(),
            None,
        )?;

        Ok(GeneratedTxnProof { p_vals, intern })
    }

    /// Generate a transaction proof using the specified input.
    ///
    /// The specific implementation depends on the persistence strategy.
    /// - If the persistence strategy is [`CircuitPersistence::None`] or
    ///   [`CircuitPersistence::Disk`] with [`TableLoadStrategy::Monolithic`],
    ///   the monolithic circuit is used.
    /// - If the persistence strategy is [`CircuitPersistence::Disk`] with
    ///   [`TableLoadStrategy::OnDemand`], the table circuits are loaded as
    ///   needed.
    pub fn generate_txn_proof(&self, input: GenerationInputs) -> anyhow::Result<GeneratedTxnProof> {
        match self.persistence {
            CircuitPersistence::None | CircuitPersistence::Disk(TableLoadStrategy::Monolithic) => {
                info!("using monolithic circuit {:?}", self);
                self.txn_proof_monolithic(input)
            }
            CircuitPersistence::Disk(TableLoadStrategy::OnDemand) => {
                info!("using on demand circuit {:?}", self);
                self.txn_proof_on_demand(input)
            }
        }
    }

    /// Initialize global prover state from the configuration.
    pub fn initialize(&self) -> anyhow::Result<()> {
        info!("initializing prover state...");

        let state = match self.persistence {
            CircuitPersistence::None => {
                info!("generating circuits...");
                ProverState {
                    state: self.circuit_config.as_all_recursive_circuits(),
                }
            }
            CircuitPersistence::Disk(strategy) => {
                info!("attempting to load preprocessed circuits from disk...");

                let disk_state = match strategy {
                    TableLoadStrategy::OnDemand => BaseProverResource::get(&self.circuit_config),
                    TableLoadStrategy::Monolithic => {
                        MonolithicProverResource::get(&self.circuit_config)
                    }
                };

                match disk_state {
                    Ok(circuits) => {
                        info!("successfully loaded preprocessed circuits from disk");
                        ProverState { state: circuits }
                    }
                    Err(_) => {
                        info!("failed to load preprocessed circuits from disk. generating circuits...");
                        let all_recursive_circuits =
                            self.circuit_config.as_all_recursive_circuits();
                        info!("saving preprocessed circuits to disk");
                        persistence::persist_all_to_disk(
                            &all_recursive_circuits,
                            &self.circuit_config,
                        )?;
                        ProverState {
                            state: all_recursive_circuits,
                        }
                    }
                }
            }
        };

        P_STATE.set(state).map_err(|_| {
            anyhow::Error::msg(
                "prover state already set. check the program logic to ensure it is only set once",
            )
            .context("setting prover state")
        })?;

        MANAGER.set(self.clone()).map_err(|_| {
            anyhow::Error::msg(
                "prover state manager already set. check the program logic to ensure it is only set once",
            )
            .context("setting prover state manager")
        })?;

        Ok(())
    }

    /// Loads a verifier state from disk or generate it.
    pub fn verifier(&self) -> anyhow::Result<VerifierState> {
        info!("initializing verifier state...");
        match self.persistence {
            CircuitPersistence::None => {
                info!("generating circuit...");
                let prover_state = self.circuit_config.as_all_recursive_circuits();
                Ok(VerifierState {
                    state: prover_state.final_verifier_data(),
                })
            }
            CircuitPersistence::Disk(_) => {
                info!("attempting to load preprocessed verifier circuit from disk...");
                let disk_state = VerifierResource::get(&self.circuit_config);

                match disk_state {
                    Ok(state) => {
                        info!("successfully loaded preprocessed verifier circuit from disk");
                        Ok(VerifierState { state })
                    }
                    Err(_) => {
                        info!("failed to load preprocessed verifier circuit from disk. generating it...");
                        let prover_state = self.circuit_config.as_all_recursive_circuits();

                        info!("saving preprocessed verifier circuit to disk");
                        let state = prover_state.final_verifier_data();
                        VerifierResource::put(&self.circuit_config, &state)?;

                        Ok(VerifierState { state })
                    }
                }
            }
        }
    }
}
