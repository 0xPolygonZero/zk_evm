use alloy::{
    primitives::B256,
    providers::Provider,
    rpc::types::eth::{BlockId, BlockNumberOrTag, BlockTransactionsKind, Withdrawal},
    transports::Transport,
};
use anyhow::Context as _;
use clap::ValueEnum;
use common::block_interval::BlockInterval;
use evm_arithmetization::proof::{BlockHashes, BlockMetadata};
use futures::{StreamExt as _, TryStreamExt as _};
use prover::ProverInput;
use trace_decoder::types::{BlockLevelData, OtherBlockData};

mod compat;
pub mod jerigon;
pub mod native;
pub mod retry;

use compat::Compat;

/// The RPC type.
#[derive(ValueEnum, Clone, Debug)]
pub enum RpcType {
    Jerigon,
    Native,
}

/// Obtain the prover input for a given block interval
pub async fn prover_input<ProviderT, TransportT>(
    provider: &ProviderT,
    block_interval: BlockInterval,
    checkpoint_block_id: BlockId,
    rpc_type: RpcType,
) -> anyhow::Result<ProverInput>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    // Grab interval checkpoint block state trie
    let checkpoint_state_trie_root = provider
        .get_block(checkpoint_block_id, BlockTransactionsKind::Hashes)
        .await?
        .context("block does not exist")?
        .header
        .state_root;

    let mut block_proofs = Vec::new();
    let mut block_interval = block_interval.into_bounded_stream()?;

    while let Some(block_num) = block_interval.next().await {
        let block_id = BlockId::Number(BlockNumberOrTag::Number(block_num));
        let block_prover_input = match rpc_type {
            RpcType::Jerigon => {
                jerigon::block_prover_input(&provider, block_id, checkpoint_state_trie_root).await?
            }
            RpcType::Native => {
                native::block_prover_input(&provider, block_id, checkpoint_state_trie_root).await?
            }
        };

        block_proofs.push(block_prover_input);
    }
    Ok(ProverInput {
        blocks: block_proofs,
    })
}

/// Fetches other block data
async fn fetch_other_block_data<ProviderT, TransportT>(
    provider: ProviderT,
    target_block_id: BlockId,
    checkpoint_state_trie_root: B256,
) -> anyhow::Result<OtherBlockData>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    let target_block = provider
        .get_block(target_block_id, BlockTransactionsKind::Hashes)
        .await?
        .context("target block does not exist")?;
    let target_block_number = target_block
        .header
        .number
        .context("target block is missing field `number`")?;
    let chain_id = provider.get_chain_id().await?;

    let mut prev_hashes = [alloy::primitives::B256::ZERO; 256];
    let concurrency = prev_hashes.len();
    futures::stream::iter(
        prev_hashes
            .iter_mut()
            .rev() // fill RTL
            .zip(std::iter::successors(Some(target_block_number), |it| {
                it.checked_sub(1)
            }))
            .map(|(dst, n)| {
                let provider = &provider;
                async move {
                    let block = provider
                        .get_block(n.into(), BlockTransactionsKind::Hashes)
                        .await
                        .context("couldn't get block")?
                        .context("no such block")?;
                    *dst = block.header.parent_hash;
                    anyhow::Ok(())
                }
            }),
    )
    .buffered(concurrency)
    .try_collect::<()>()
    .await
    .context("couldn't fill previous hashes")?;

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
            },
            b_hashes: BlockHashes {
                prev_hashes: prev_hashes.map(|it| it.compat()).into(),
                cur_hash: target_block
                    .header
                    .hash
                    .context("target block is missing field `hash`")?
                    .compat(),
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
    };
    Ok(other_data)
}
