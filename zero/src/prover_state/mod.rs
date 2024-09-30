//! Global prover state management and utilities.
//!
//! This module provides the following:
//! - [`ProverState`] and [`CircuitConfig`] which can be used to dynamically
//!   construct [`evm_arithmetization::AllRecursiveCircuits`] from the specified
//!   circuit sizes.
//! - Command line arguments for constructing a [`CircuitConfig`].
//!     - Provides default values for the circuit sizes.
//!     - Allows the circuit sizes to be specified via environment variables.
//! - Persistence utilities for saving and loading
//!   [`evm_arithmetization::AllRecursiveCircuits`].
//! - Global prover state management via the `P_STATE` static and the
//!   [`p_state`] function.
use std::borrow::Borrow;
use std::{fmt::Display, sync::OnceLock};

use clap::ValueEnum;
use evm_arithmetization::{
    fixed_recursive_verifier::ProverOutputData, prover::prove, AllProof, AllRecursiveCircuits,
    AllStark, GenerationSegmentData, RecursiveCircuitsForTableSize, StarkConfig,
    TrimmedGenerationInputs,
};
use evm_arithmetization::{ProofWithPublicInputs, ProofWithPublicValues, VerifierData};
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use plonky2::util::timing::TimingTree;
use tracing::info;

use self::circuit::{CircuitConfig, NUM_TABLES};
use crate::prover_state::persistence::{
    BaseProverResource, DiskResource, MonolithicProverResource, RecursiveCircuitResource,
    VerifierResource,
};

pub mod circuit;
pub mod cli;
pub mod persistence;

/// zkEVM proving state, needed to generate succinct block proofs for EVM-based
/// chains.
pub struct ProverState {
    /// The set of pre-processed circuits to recursively prove blocks.
    pub state: AllRecursiveCircuits,
}

/// zkEVM verifier state, useful for verifying generated block proofs.
///
/// This requires much less memory than its prover counterpart.
pub struct VerifierState {
    /// The verification circuit data associated to the block proof layer of the
    /// zkEVM prover state.
    pub state: VerifierData,
}

/// Extracts the verifier state from the entire prover state.
impl<T: Borrow<ProverState>> From<T> for VerifierState {
    fn from(prover_state: T) -> Self {
        VerifierState {
            state: prover_state.borrow().state.final_verifier_data(),
        }
    }
}

impl VerifierState {
    /// Verifies a `block_proof`.
    pub fn verify(&self, block_proof: &ProofWithPublicInputs) -> anyhow::Result<()> {
        // Proof verification
        self.state.verify(block_proof.clone())?;

        // Verifier data verification
        check_cyclic_proof_verifier_data(block_proof, &self.state.verifier_only, &self.state.common)
    }
}

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
    pub const fn with_load_strategy(self, load_strategy: TableLoadStrategy) -> Self {
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
        all_proof: &AllProof,
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
            circuit!(7),
            circuit!(8),
            #[cfg(feature = "cdk_erigon")]
            circuit!(9),
        ])
    }

    /// Generate a segment proof using the specified input, loading
    /// the circuit tables as needed to shrink the individual STARK proofs,
    /// and finally aggregating them to a final transaction proof.
    fn segment_proof_on_demand(
        &self,
        input: TrimmedGenerationInputs,
        segment_data: &mut GenerationSegmentData,
    ) -> anyhow::Result<ProofWithPublicValues> {
        let config = StarkConfig::standard_fast_config();
        let all_stark = AllStark::default();

        let all_proof = prove(
            &all_stark,
            &config,
            input,
            segment_data,
            &mut TimingTree::default(),
            None,
        )?;

        let table_circuits = self.load_table_circuits(&config, &all_proof)?;

        let proof_with_pvs =
            p_state()
                .state
                .prove_segment_after_initial_stark(all_proof, &table_circuits, None)?;

        Ok(proof_with_pvs)
    }

    /// Generate a segment proof using the specified input on the monolithic
    /// circuit.
    fn segment_proof_monolithic(
        &self,
        input: TrimmedGenerationInputs,
        segment_data: &mut GenerationSegmentData,
    ) -> anyhow::Result<ProofWithPublicValues> {
        let p_out = p_state().state.prove_segment(
            &AllStark::default(),
            &StarkConfig::standard_fast_config(),
            input,
            segment_data,
            &mut TimingTree::default(),
            None,
        )?;

        let ProverOutputData {
            is_agg: _,
            is_dummy: _,
            proof_with_pvs,
        } = p_out;

        Ok(proof_with_pvs)
    }

    /// Generate a segment proof using the specified input.
    ///
    /// The specific implementation depends on the persistence strategy.
    /// - If the persistence strategy is [`CircuitPersistence::None`] or
    ///   [`CircuitPersistence::Disk`] with [`TableLoadStrategy::Monolithic`],
    ///   the monolithic circuit is used.
    /// - If the persistence strategy is [`CircuitPersistence::Disk`] with
    ///   [`TableLoadStrategy::OnDemand`], the table circuits are loaded as
    ///   needed.
    pub fn generate_segment_proof(
        &self,
        input: (TrimmedGenerationInputs, GenerationSegmentData),
    ) -> anyhow::Result<ProofWithPublicValues> {
        let (generation_inputs, mut segment_data) = input;

        match self.persistence {
            CircuitPersistence::None | CircuitPersistence::Disk(TableLoadStrategy::Monolithic) => {
                info!("using monolithic circuit {:?}", self);
                self.segment_proof_monolithic(generation_inputs, &mut segment_data)
            }
            CircuitPersistence::Disk(TableLoadStrategy::OnDemand) => {
                info!("using on demand circuit {:?}", self);
                self.segment_proof_on_demand(generation_inputs, &mut segment_data)
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
