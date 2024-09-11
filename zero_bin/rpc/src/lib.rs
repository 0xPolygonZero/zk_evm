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
compile_error!("Only a single network feature should be enabled at a time!");

use std::sync::Arc;

use __compat_primitive_types::{H256, U256};
use alloy::{
    primitives::{Address, Bytes, FixedBytes, B256},
    providers::Provider,
    rpc::types::eth::{BlockId, BlockTransactionsKind, Withdrawal},
    transports::Transport,
};
use anyhow::{anyhow, Context as _};
use clap::ValueEnum;
use compat::Compat;
use evm_arithmetization::proof::{BlockHashes, BlockMetadata};
use futures::{StreamExt as _, TryStreamExt as _};
use prover::BlockProverInput;
use serde_json::json;
use trace_decoder::{BlockLevelData, OtherBlockData};
use tracing::warn;

pub mod jerigon;
pub mod native;
pub mod retry;

use zero_bin_common::provider::CachedProvider;

pub(crate) type PreviousBlockHashes = [FixedBytes<32>; 256];

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
    checkpoint_state_trie_root: B256,
    rpc_type: RpcType,
) -> Result<BlockProverInput, anyhow::Error>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    match rpc_type {
        RpcType::Jerigon => {
            jerigon::block_prover_input(cached_provider, block_id, checkpoint_state_trie_root).await
        }
        RpcType::Native => {
            native::block_prover_input(cached_provider, block_id, checkpoint_state_trie_root).await
        }
    }
}

async fn fetch_previous_block_hashes_from_block<ProviderT, TransportT>(
    cached_provider: Arc<CachedProvider<ProviderT, TransportT>>,
    target_block_number: u64,
) -> anyhow::Result<PreviousBlockHashes>
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
                        (block.header.parent_hash, previous_block_number),
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
            if let (hash, Some(block_num)) = (hash, block_num) {
                // Most recent previous block hash is expected at the end of the array
                prev_hashes
                    [PREVIOUS_HASHES_COUNT - (target_block_number - block_num as u64) as usize] =
                    hash;
            }
        });

    Ok(prev_hashes)
}

async fn fetch_previous_block_hashes_smart_contract<ProviderT, TransportT>(
    cached_provider: Arc<CachedProvider<ProviderT, TransportT>>,
    target_block_number: u64,
) -> anyhow::Result<PreviousBlockHashes>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    // Here, we perform the `eth_call` to the node to get the previous
    // block hashes (read-only execution). We set the target address to be
    // empty, hence the node executes this call as a contract creation function.
    // We use that execution not to produce a new contract bytecode - instead, we
    // return hashes. To look at the code use `cast disassemble <bytecode>`.
    let bytes = cached_provider
        .get_provider()
        .await?
        .raw_request::<_, Bytes>(
            "eth_call".into(),
            (
                json!({"data": "0x60005B60010180430340816020025280610101116300000002576120205FF3"}),
                &format!("{:#x}", target_block_number),
            ),
        )
        .await?;

    let prev_hashes = bytes
        .chunks(32)
        .skip(1) // blockhash for current block
        .map(FixedBytes::<32>::try_from)
        .rev()
        .collect::<Result<Vec<_>, _>>()?;

    PreviousBlockHashes::try_from(prev_hashes)
        .map_err(|_| anyhow!("invalid conversion to 256 previous block hashes"))
}

async fn fetch_previous_block_hashes<ProviderT, TransportT>(
    cached_provider: Arc<CachedProvider<ProviderT, TransportT>>,
    target_block_number: u64,
) -> anyhow::Result<PreviousBlockHashes>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    match fetch_previous_block_hashes_smart_contract(cached_provider.clone(), target_block_number)
        .await
    {
        Ok(prev_block_hahes) => {
            if !prev_block_hahes.into_iter().all(|it| it.0 == [0u8; 32]) {
                // Previous hashes valid, return result
                return Ok(prev_block_hahes);
            } else {
                warn!("all retrieved block hashes empty, falling back to `eth_getBlockByNumber` for block {}", target_block_number);
            }
        }
        Err(e) => {
            warn!("unable to retrieve previous block hashes with `eth_call`: {e}");
        }
    }

    fetch_previous_block_hashes_from_block(cached_provider, target_block_number).await
}

/// Fetches other block data
async fn fetch_other_block_data<ProviderT, TransportT>(
    cached_provider: Arc<CachedProvider<ProviderT, TransportT>>,
    target_block_id: BlockId,
    checkpoint_state_trie_root: B256,
) -> anyhow::Result<OtherBlockData>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    let target_block = cached_provider
        .get_block(target_block_id, BlockTransactionsKind::Hashes)
        .await?;
    let target_block_number = target_block.header.number;
    let chain_id = cached_provider.get_provider().await?.get_chain_id().await?;
    let prev_hashes = fetch_previous_block_hashes(cached_provider, target_block_number).await?;

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
                block_base_fee: if !cfg!(feature = "cdk_erigon") {
                    target_block
                        .header
                        .base_fee_per_gas
                        .context("target block is missing field `base_fee_per_gas`")?
                        .into()
                } else {
                    target_block
                        .header
                        .base_fee_per_gas
                        .unwrap_or_default() // `baseFee` may be disabled to enable 0 price calls (EIP-1559)
                        .into()
                },
                block_gas_used: target_block.header.gas_used.into(),
                block_bloom: target_block.header.logs_bloom.compat(),
                parent_beacon_block_root: if cfg!(feature = "eth_mainnet") {
                    target_block
                        .header
                        .parent_beacon_block_root
                        .context("target block is missing field `parent_beacon_block_root`")?
                        .compat()
                } else {
                    H256::zero()
                },
                block_blob_gas_used: if cfg!(feature = "eth_mainnet") {
                    target_block
                        .header
                        .blob_gas_used
                        .context("target block is missing field `blob_gas_used`")?
                        .into()
                } else {
                    U256::zero()
                },
                block_excess_blob_gas: if cfg!(feature = "eth_mainnet") {
                    target_block
                        .header
                        .excess_blob_gas
                        .context("target block is missing field `excess_blob_gas`")?
                        .into()
                } else {
                    U256::zero()
                },
            },
            b_hashes: BlockHashes {
                prev_hashes: prev_hashes.map(|it| it.compat()).into(),
                cur_hash: target_block.header.hash.compat(),
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
        burn_addr: if cfg!(feature = "cdk_erigon") {
            // TODO: https://github.com/0xPolygonZero/zk_evm/issues/565
            //       Retrieve the actual burn address from `cdk-erigon`.
            Some(Address::ZERO.compat())
        } else {
            None
        },
    };
    Ok(other_data)
}
