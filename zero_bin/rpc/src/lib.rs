use alloy::{
    providers::Provider,
    rpc::types::eth::{BlockId, Withdrawal},
    transports::Transport,
};
use anyhow::Context as _;
use common::Compat as _;
use evm_arithmetization::proof::{BlockHashes, BlockMetadata};
use futures::{StreamExt as _, TryStreamExt as _};
use itertools::{Either, Itertools as _};
use prover::ProverInput;
use serde::Deserialize;
use serde_json::json;
use trace_decoder::{
    trace_protocol::{BlockTrace, BlockTraceTriePreImages, TxnInfo},
    types::{BlockLevelData, OtherBlockData},
};

#[derive(Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
enum JerigonTrace {
    Result(TxnInfo),
    BlockWitness(BlockTraceTriePreImages),
}

const BLOCK_WITHOUT_FULL_TRANSACTIONS: bool = false;

pub async fn prover_input<ProviderT, TransportT>(
    provider: ProviderT,
    target_block_id: BlockId,
    checkpoint_block_id: BlockId,
) -> anyhow::Result<ProverInput>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    // Grab trace information
    /////////////////////////
    let traces = provider
        .raw_request::<_, Vec<JerigonTrace>>(
            "debug_traceBlockByNumber".into(),
            (target_block_id, json!({"tracer": "zeroTracer"})),
        )
        .await?;

    let (txn_info, mut pre_images) =
        traces
            .into_iter()
            .partition_map::<Vec<_>, Vec<_>, _, _, _>(|it| match it {
                JerigonTrace::Result(it) => Either::Left(it),
                JerigonTrace::BlockWitness(it) => Either::Right(it),
            });

    // Grab block info
    //////////////////
    let target_block = provider
        .get_block(target_block_id, BLOCK_WITHOUT_FULL_TRANSACTIONS)
        .await?
        .context("target block does not exist")?;
    let target_block_number = target_block
        .header
        .number
        .context("target block is missing field `number`")?;
    let chain_id = provider.get_chain_id().await?;
    let checkpoint_state_trie_root = provider
        .get_block(checkpoint_block_id, BLOCK_WITHOUT_FULL_TRANSACTIONS)
        .await?
        .context("checkpoint block does not exist")?
        .header
        .state_root;

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
                        .get_block(n.into(), BLOCK_WITHOUT_FULL_TRANSACTIONS)
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

    // Assemble
    ///////////
    Ok(ProverInput {
        block_trace: BlockTrace {
            trie_pre_images: pre_images.pop().context("trace had no BlockWitness")?,
            txn_info,
        },
        other_data: OtherBlockData {
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
        },
    })
}
