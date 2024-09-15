zk_evm_common::check_chain_features!();

pub mod block_interval;
pub mod debug_utils;
pub mod env;
pub mod fs;
pub mod parsing;
pub mod pre_checks;
pub mod proof_runtime;
pub mod prover_state;
pub mod provider;
pub mod tracing;
pub mod version;

/// Size of the channel used to send block prover inputs to the per block
/// proving task. If the proving task is slow and can not consume inputs fast
/// enough retrieval of the block prover inputs will block until the proving
/// task consumes some of the inputs.
pub const BLOCK_CHANNEL_SIZE: usize = 16;
