//! This is useful for fetching [ProverInput] per block
use alloy::{
    providers::RootProvider,
    rpc::types::{BlockId, BlockNumberOrTag},
};
use anyhow::Error;
use rpc::{benchmark_prover_input, BenchmarkedProverInput};
use tracing::info;
use zero_bin_common::block_interval::BlockInterval;

use super::input::BlockSource;

//==============================================================================
// FetchError
//==============================================================================
#[derive(Debug)]
pub enum FetchError {
    ZeroBinRpcFetchError(Error),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self, f)
    }
}

impl std::error::Error for FetchError {}

//=============================================================================
// Fetching
//=============================================================================

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum Checkpoint {
    Default,
    Constant(BlockId),
    BlockNumberNegativeOffset(u64),
}

unsafe impl Send for Checkpoint {}

impl Default for Checkpoint {
    fn default() -> Self {
        Self::BlockNumberNegativeOffset(1)
    }
}

impl Checkpoint {
    pub fn get_checkpoint_from_blocknum(&self, block_number: u64) -> BlockId {
        match self {
            Self::Constant(num @ BlockId::Number(_)) => *num,
            Self::Constant(BlockId::Hash(_)) => {
                unreachable!("Coordinator does not support Hash Block IDs")
            }
            Self::BlockNumberNegativeOffset(offset) => {
                BlockId::Number(BlockNumberOrTag::Number(block_number - *offset))
            }
            _ => BlockId::Number(BlockNumberOrTag::Number(block_number - 1)),
        }
    }

    pub fn get_checkpoint_from_interval(&self, block_interval: BlockInterval) -> BlockId {
        match block_interval {
            BlockInterval::FollowFrom {
                start_block,
                block_time: _,
            } => self.get_checkpoint_from_blocknum(start_block),
            BlockInterval::Range(range) => self.get_checkpoint_from_blocknum(range.start),
            BlockInterval::SingleBlockId(BlockId::Number(BlockNumberOrTag::Number(start))) => {
                self.get_checkpoint_from_blocknum(start)
            }
            BlockInterval::SingleBlockId(BlockId::Number(_) | BlockId::Hash(_)) => {
                todo!("Coordinator only supports Numbers, not Tags or Block Hashes")
            }
        }
    }
}

/// Fetches the prover input given the [BlockSource]
pub async fn fetch(
    block_interval: BlockInterval,
    checkpoint_method: &Option<Checkpoint>,
    source: &BlockSource,
) -> Result<BenchmarkedProverInput, FetchError> {
    match source {
        // Use ZeroBing's RPC fetch
        BlockSource::ZeroBinRpc { rpc_url } => {
            info!(
                "Requesting from block {} from RPC ({})",
                block_interval, rpc_url
            );

            let checkpoint = checkpoint_method
                .unwrap_or_default()
                .get_checkpoint_from_interval(block_interval.clone());

            let provider_url = match url::Url::parse(rpc_url) {
                Ok(url) => url,
                Err(err) => return Err(FetchError::ZeroBinRpcFetchError(err.into())),
            };

            match benchmark_prover_input(
                &RootProvider::new_http(provider_url),
                block_interval,
                checkpoint,
                rpc::RpcType::Jerigon,
            )
            .await
            {
                Ok(input) => Ok(input),
                Err(err) => Err(FetchError::ZeroBinRpcFetchError(err)),
            }
        }
    }
}
