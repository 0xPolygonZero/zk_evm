zk_evm_common::check_chain_features!();

pub mod block_interval;
pub mod debug_utils;
pub mod env;
pub mod fs;
pub mod ops;
pub mod pre_checks;
pub mod proof_types;
pub mod prover;
pub mod prover_state;
pub mod provider;
pub mod rpc;
pub mod tracing;
pub mod trie_diff;

/// Size of the channel used to send block prover inputs to the per block
/// proving task. If the proving task is slow and can not consume inputs fast
/// enough retrieval of the block prover inputs will block until the proving
/// task consumes some of the inputs.
pub const BLOCK_CHANNEL_SIZE: usize = 16;

/// Common information for the `--version` CLI flags.
pub fn version() -> String {
    let pkg_name = env!("CARGO_PKG_NAME");
    let git_describe = env!("VERGEN_GIT_DESCRIBE");
    let timestamp = env!("VERGEN_BUILD_TIMESTAMP");
    let kernel_hash = &**prover_state::persistence::KERNEL_HASH;
    format!("{pkg_name} ({git_describe}) (kernel hash: {kernel_hash}) [built: {timestamp}]")
}
