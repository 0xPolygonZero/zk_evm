#[cfg(any(
    all(feature = "cdk_erigon", feature = "polygon_pos"),
    all(feature = "cdk_erigon", feature = "eth_mainnet"),
    all(feature = "polygon_pos", feature = "eth_mainnet"),
    not(any(
        feature = "cdk_erigon",
        feature = "eth_mainnet",
        feature = "polygon_pos"
    ))
))]
compile_error!("One and only one of the feature chains `cdk_erigon`, `polygon_pos` or `eth_mainnet` must be selected");
pub mod block_interval;

pub mod debug_utils;
pub mod fs;
pub mod parsing;
pub mod pre_checks;
pub mod prover_state;
pub mod provider;
pub mod version;

/// Size of the channel used to send block prover inputs to the per block
/// proving task. If the proving task is slow and can not consume inputs fast
/// enough retrieval of the block prover inputs will block until the proving
/// task consumes some of the inputs.
pub const BLOCK_CHANNEL_SIZE: usize = 16;
