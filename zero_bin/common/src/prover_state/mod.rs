//! Global prover state management and utilities.
//!
//! This module provides the following:
//! - [`Circuit`] and [`CircuitConfig`] which can be used to dynamically
//!   construct [`AllRecursiveCircuits`] from the specified circuit sizes.
//! - Command line arguments for constructing a [`CircuitConfig`].
//!     - Provides default values for the circuit sizes.
//!     - Allows the circuit sizes to be specified via environment variables.
//! - Persistence utilities for saving and loading [`AllRecursiveCircuits`].
//! - Global prover state management via the [`P_STATE`] static and the
//!   [`set_prover_state_from_config`] function.
use std::{fmt::Display, sync::OnceLock};

use clap::ValueEnum;
use plonky_block_proof_gen::{prover_state::ProverState, VerifierState};
use tracing::info;

pub mod circuit;
pub mod cli;
pub mod persistence;

/// The global prover state.
///
/// It is specified as a `OnceLock` for the following reasons:
/// - It is initialized once at start-up and never changed.
/// - It is accessible from multiple threads (particularly important when
///   running the leader in in-memory mode).
/// - This scheme works for both a cluster and a single machine. In particular,
///   whether imported from a worker node or a thread in the leader node
///   (in-memory mode), the prover state is initialized only once.
pub static P_STATE: OnceLock<ProverState> = OnceLock::new();

/// Specifies whether to persist the processed circuits.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CircuitPersistence {
    /// Do not persist the processed circuits.
    None,
    /// Persist the processed circuits to disk.
    Disk,
}

impl Display for CircuitPersistence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitPersistence::None => write!(f, "none"),
            CircuitPersistence::Disk => write!(f, "disk"),
        }
    }
}

/// Product of [`CircuitConfig`] and [`CircuitPersistence`].
#[derive(Debug)]
pub struct ProverStateConfig {
    pub circuit_config: circuit::CircuitConfig,
    pub persistence: CircuitPersistence,
}

/// Initializes the global prover state.
pub fn set_prover_state_from_config(
    ProverStateConfig {
        circuit_config,
        persistence,
    }: ProverStateConfig,
) -> Result<(), ProverState> {
    info!("initializing prover state...");
    let state = match persistence {
        CircuitPersistence::None => {
            info!("generating circuits...");
            ProverState {
                state: circuit_config.as_all_recursive_circuits(),
            }
        }
        CircuitPersistence::Disk => {
            info!("attempting to load preprocessed circuits from disk...");
            let disk_state = persistence::prover_from_disk(&circuit_config);
            match disk_state {
                Some(circuits) => {
                    info!("successfully loaded preprocessed circuits from disk");
                    ProverState { state: circuits }
                }
                None => {
                    info!("failed to load preprocessed circuits from disk. generating circuits...");
                    let all_recursive_circuits = circuit_config.as_all_recursive_circuits();
                    info!("saving preprocessed circuits to disk");
                    persistence::to_disk(&all_recursive_circuits, &circuit_config);
                    ProverState {
                        state: all_recursive_circuits,
                    }
                }
            }
        }
    };

    P_STATE.set(state)
}

/// Loads a verifier state from disk or generate it.
pub fn get_verifier_state_from_config(
    ProverStateConfig {
        circuit_config,
        persistence,
    }: ProverStateConfig,
) -> VerifierState {
    info!("initializing verifier state...");
    match persistence {
        CircuitPersistence::None => {
            info!("generating circuit...");
            let prover_state = circuit_config.as_all_recursive_circuits();
            VerifierState {
                state: prover_state.final_verifier_data(),
            }
        }
        CircuitPersistence::Disk => {
            info!("attempting to load preprocessed verifier circuit from disk...");
            let disk_state = persistence::verifier_from_disk(&circuit_config);
            match disk_state {
                Some(state) => {
                    info!("successfully loaded preprocessed verifier circuit from disk");
                    VerifierState { state }
                }
                None => {
                    info!(
                        "failed to load preprocessed verifier circuit from disk. generating it..."
                    );
                    let prover_state = circuit_config.as_all_recursive_circuits();

                    info!("saving preprocessed verifier circuit to disk");
                    let state = prover_state.final_verifier_data();
                    persistence::verifier_to_disk(&state, &circuit_config);

                    VerifierState { state }
                }
            }
        }
    }
}
