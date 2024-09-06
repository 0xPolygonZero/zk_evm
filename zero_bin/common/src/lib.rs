#[cfg_attr(
    not(any(feature = "polygon_pos", feature = "cdk_erigon")),
    cfg(feature = "eth_mainnet")
)]
#[cfg(any(
    all(feature = "cdk_erigon", feature = "polygon_pos"),
    all(feature = "cdk_erigon", feature = "eth_mainnet"),
    all(feature = "polygon_pos", feature = "eth_mainnet"),
))]
compile_error!("Only a single network feature should be enabled at a time!");
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
