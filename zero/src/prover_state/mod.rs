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
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::sync::OnceLock;

use evm_arithmetization::testing_utils::TEST_STARK_CONFIG;
use evm_arithmetization::{
    fixed_recursive_verifier::ProverOutputData, AllRecursiveCircuits, AllStark,
    GenerationSegmentData, StarkConfig, TrimmedGenerationInputs,
};
use evm_arithmetization::{ProofWithPublicInputs, ProofWithPublicValues, VerifierData};
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use plonky2::util::timing::TimingTree;
use tracing::info;

use self::circuit::CircuitConfig;
use crate::prover_state::persistence::{DiskResource, MonolithicProverResource, VerifierResource};

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

/// Specifies whether to persist the processed circuits.
#[derive(Debug, Clone, Copy)]
pub enum CircuitPersistence {
    /// Do not persist the processed circuits.
    None,
    /// Persist the processed circuits to disk.
    Disk,
}

impl Default for CircuitPersistence {
    fn default() -> Self {
        CircuitPersistence::Disk
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
    /// Generate a segment proof using the specified input on the monolithic
    /// circuit.
    fn segment_proof_monolithic(
        &self,
        input: TrimmedGenerationInputs,
        segment_data: &mut GenerationSegmentData,
        config: &StarkConfig,
        abort_signal: Option<Arc<AtomicBool>>,
    ) -> anyhow::Result<ProofWithPublicValues> {
        let p_out = p_state().state.prove_segment(
            &AllStark::default(),
            config,
            input,
            segment_data,
            &mut TimingTree::default(),
            abort_signal,
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
        abort_signal: Option<Arc<AtomicBool>>,
    ) -> anyhow::Result<ProofWithPublicValues> {
        let (generation_inputs, mut segment_data) = input;
        let config = if self.circuit_config.use_test_config {
            TEST_STARK_CONFIG
        } else {
            StarkConfig::standard_fast_config()
        };

        self.segment_proof_monolithic(generation_inputs, &mut segment_data, &config, abort_signal)
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
            CircuitPersistence::Disk => {
                info!("attempting to load preprocessed circuits from disk...");

                let disk_state = MonolithicProverResource::get(&self.circuit_config);

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
            CircuitPersistence::Disk => {
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
