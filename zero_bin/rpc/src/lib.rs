use std::sync::Arc;

use alloy::{
    primitives::B256,
    providers::Provider,
    rpc::types::eth::{BlockId, BlockTransactionsKind, Withdrawal},
    transports::Transport,
};
use anyhow::Context as _;
use clap::ValueEnum;
use compat::Compat;
use evm_arithmetization::proof::{consolidate_hashes, BlockHashes, BlockMetadata};
use futures::{StreamExt as _, TryStreamExt as _};
use proof_gen::types::{Field, Hasher};
use prover::BlockProverInput;
use trace_decoder::{BlockLevelData, OtherBlockData};

pub mod jerigon;
pub mod native;
pub mod provider;
pub mod retry;

use crate::provider::CachedProvider;

const PREVIOUS_HASHES_COUNT: usize = 256;

/// The RPC type.
#[derive(ValueEnum, Clone, Debug, Copy)]
pub enum RpcType {
    Jerigon,
    Native,
}

/// Obtain the prover input for one block
pub async fn block_prover_input<ProviderT, TransportT>(
    cached_provider: Arc<CachedProvider<ProviderT, TransportT>>,
    block_id: BlockId,
    checkpoint_block_number: u64,
    rpc_type: RpcType,
) -> Result<BlockProverInput, anyhow::Error>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    match rpc_type {
        RpcType::Jerigon => {
            jerigon::block_prover_input(cached_provider, block_id, checkpoint_block_number).await
        }
        RpcType::Native => {
            native::block_prover_input(cached_provider, block_id, checkpoint_block_number).await
        }
    }
}

/// Fetches other block data
async fn fetch_other_block_data<ProviderT, TransportT>(
    cached_provider: Arc<CachedProvider<ProviderT, TransportT>>,
    target_block_id: BlockId,
    checkpoint_block_number: u64,
) -> anyhow::Result<OtherBlockData>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    let target_block = cached_provider
        .get_block(target_block_id, BlockTransactionsKind::Hashes)
        .await?;
    let target_block_number = target_block
        .header
        .number
        .context("target block is missing field `number`")?;
    let chain_id = cached_provider.as_provider().get_chain_id().await?;

    // Grab interval checkpoint block state trie
    let checkpoint_state_trie_root = cached_provider
        .get_block(
            checkpoint_block_number.into(),
            BlockTransactionsKind::Hashes,
        )
        .await?
        .header
        .state_root;

    let prev_hashes = fetch_block_hashes(cached_provider.clone(), target_block_number).await?;
    let checkpoint_prev_hashes = fetch_block_hashes(cached_provider, checkpoint_block_number)
        .await?
        .map(|it| it.compat());

    let other_data = OtherBlockData {
        b_data: BlockLevelData {
            b_meta: BlockMetadata {
                block_beneficiary: target_block.header.miner.compat(),
                block_timestamp: target_block.header.timestamp.into(),
                block_number: target_block_number.into(),
                block_difficulty: target_block.header.difficulty.into(),
                block_random: target_block
                    .header
                    .mix_hash
                    .context("target block is missing field `mix_hash`")?
                    .compat(),
                block_gaslimit: target_block.header.gas_limit.into(),
                block_chain_id: chain_id.into(),
                block_base_fee: target_block
                    .header
                    .base_fee_per_gas
                    .context("target block is missing field `base_fee_per_gas`")?
                    .into(),
                block_gas_used: target_block.header.gas_used.into(),
                block_bloom: target_block.header.logs_bloom.compat(),
                parent_beacon_block_root: target_block
                    .header
                    .parent_beacon_block_root
                    .context("target block is missing field `parent_beacon_block_root`")?
                    .compat(),
                block_blob_gas_used: target_block
                    .header
                    .blob_gas_used
                    .context("target block is missing field `blob_gas_used`")?
                    .into(),
                block_excess_blob_gas: target_block
                    .header
                    .excess_blob_gas
                    .context("target block is missing field `excess_blob_gas`")?
                    .into(),
            },
            b_hashes: BlockHashes {
                prev_hashes: prev_hashes.map(|it| it.compat()).into(),
                cur_hash: target_block
                    .header
                    .hash
                    .context("target block is missing field `hash`")?
                    .compat(),
                consolidated_hash: None,
            },
            withdrawals: target_block
                .withdrawals
                .into_iter()
                .flatten()
                .map(
                    |Withdrawal {
                         address, amount, ..
                     }| { (address.compat(), amount.into()) },
                )
                .collect(),
        },
        checkpoint_state_trie_root: checkpoint_state_trie_root.compat(),
        checkpoint_consolidated_hash: consolidate_hashes::<Hasher, Field>(&checkpoint_prev_hashes),
    };
    Ok(other_data)
}

async fn fetch_block_hashes<ProviderT, TransportT>(
    cached_provider: Arc<CachedProvider<ProviderT, TransportT>>,
    target_block_number: u64,
) -> anyhow::Result<[B256; PREVIOUS_HASHES_COUNT]>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    use itertools::Itertools;
    // For one block, we will fetch 128 previous blocks to get hashes instead of
    // 256. But for two consecutive blocks (odd and even) we would fetch 256
    // previous blocks in total. To overcome this, we add an offset so that we
    // always start fetching from an odd index and eventually skip the additional
    // block for an even `target_block_number`.
    let odd_offset: i128 = target_block_number as i128 % 2;

    let previous_block_numbers =
        std::iter::successors(Some(target_block_number as i128 - 1 + odd_offset), |&it| {
            Some(it - 1)
        })
        .take(PREVIOUS_HASHES_COUNT + 1)
        .filter(|i| *i >= 0)
        .chunks(2)
        .into_iter()
        .map(|mut chunk| {
            // We convert to tuple of (current block, optional previous block)
            let first = chunk
                .next()
                .expect("must be valid according to itertools::Iterator::chunks definition");
            let second = chunk.next();
            (first, second)
        })
        .collect::<Vec<_>>();

    let concurrency = previous_block_numbers.len();
    let collected_hashes = futures::stream::iter(
        previous_block_numbers
            .into_iter() // we get hash for previous and current block with one request
            .map(|(current_block_number, previous_block_number)| {
                let cached_provider = &cached_provider;
                let block_num = current_block_number;
                async move {
                    let block = cached_provider
                        .get_block((block_num as u64).into(), BlockTransactionsKind::Hashes)
                        .await
                        .context("couldn't get block")?;
                    anyhow::Ok([
                        (block.header.hash, Some(block_num)),
                        (Some(block.header.parent_hash), previous_block_number),
                    ])
                }
            }),
    )
    .buffered(concurrency)
    .try_collect::<Vec<_>>()
    .await
    .context("couldn't fill previous hashes")?;

    let mut prev_hashes = [B256::ZERO; PREVIOUS_HASHES_COUNT];
    collected_hashes
        .into_iter()
        .flatten()
        .skip(odd_offset as usize)
        .take(PREVIOUS_HASHES_COUNT)
        .for_each(|(hash, block_num)| {
            if let (Some(hash), Some(block_num)) = (hash, block_num) {
                // Most recent previous block hash is expected at the end of the array
                prev_hashes
                    [PREVIOUS_HASHES_COUNT - (target_block_number - block_num as u64) as usize] =
                    hash;
            }
        });

    Ok(prev_hashes)
}
