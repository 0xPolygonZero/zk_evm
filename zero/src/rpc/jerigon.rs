use std::collections::BTreeMap;
use std::ops::Deref as _;

use alloy::{
    providers::Provider,
    rpc::types::{eth::BlockId, trace::geth::StructLog, Block, BlockTransactionsKind, Transaction},
    transports::Transport,
};
use alloy_primitives::Address;
use anyhow::Context as _;
use evm_arithmetization::jumpdest::JumpDestTableWitness;
use futures::stream::FuturesOrdered;
use futures::StreamExt as _;
use serde::Deserialize;
use serde_json::json;
use trace_decoder::{
    BlockTrace, BlockTraceTriePreImages, CombinedPreImages, TxnInfo, TxnMeta, TxnTrace,
};
use tracing::info;

use super::{
    fetch_other_block_data,
    jumpdest::{self, get_normalized_structlog},
};
use crate::prover::BlockProverInput;
use crate::provider::CachedProvider;
/// Transaction traces retrieved from Erigon zeroTracer.
#[derive(Debug, Deserialize)]
pub struct ZeroTxResult {
    #[serde(rename(deserialize = "txHash"))]
    pub tx_hash: alloy::primitives::TxHash,
    pub result: TxnInfo,
}

pub async fn block_prover_input<ProviderT, TransportT>(
    cached_provider: std::sync::Arc<CachedProvider<ProviderT, TransportT>>,
    target_block_id: BlockId,
    checkpoint_block_number: u64,
) -> anyhow::Result<BlockProverInput>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    // Grab trace information
    let tx_results = cached_provider
        .get_provider()
        .await?
        .raw_request::<_, Vec<ZeroTxResult>>(
            "debug_traceBlockByNumber".into(),
            (target_block_id, json!({"tracer": "zeroTracer"})),
        )
        .await?
        .into_iter()
        .map(|ztr| ztr.result)
        .collect::<Vec<_>>();

    // Grab block witness info (packed as combined trie pre-images)
    let block_witness = cached_provider
        .get_provider()
        .await?
        .raw_request::<_, String>("eth_getWitness".into(), vec![target_block_id])
        .await?;

    let block = cached_provider
        .get_block(target_block_id, BlockTransactionsKind::Full)
        .await?;

    let tx_traces: Vec<&BTreeMap<__compat_primitive_types::H160, TxnTrace>> = tx_results
        .iter()
        .map(|TxnInfo { traces, meta: _ }| traces)
        .collect::<Vec<_>>();

    let jdts: Vec<Option<JumpDestTableWitness>> = process_transactions(
        &block,
        cached_provider.get_provider().await?.deref(),
        &tx_traces,
    )
    .await?;

    // weave in the JDTs
    let txn_info = tx_results
        .into_iter()
        .zip(jdts)
        .map(
            |(
                TxnInfo {
                    traces,
                    meta:
                        TxnMeta {
                            byte_code,
                            new_receipt_trie_node_byte,
                            gas_used,
                            jumpdest_table: _,
                        },
                },
                jdt,
            )| TxnInfo {
                traces,
                meta: TxnMeta {
                    byte_code,
                    new_receipt_trie_node_byte,
                    gas_used,
                    jumpdest_table: jdt,
                },
            },
        )
        .collect();

    let other_data =
        fetch_other_block_data(cached_provider, target_block_id, checkpoint_block_number).await?;

    // Assemble
    Ok(BlockProverInput {
        block_trace: BlockTrace {
            trie_pre_images: BlockTraceTriePreImages::Combined(CombinedPreImages {
                compact: hex::decode(block_witness.strip_prefix("0x").unwrap_or(&block_witness))
                    .context("invalid hex returned from call to eth_getWitness")?,
            }),
            txn_info,
            code_db: Default::default(),
        },
        other_data,
    })
}

/// Processes the transactions in the given block and updates the code db.
pub async fn process_transactions<ProviderT, TransportT>(
    block: &Block,
    provider: &ProviderT,
    tx_traces: &[&BTreeMap<__compat_primitive_types::H160, TxnTrace>],
) -> anyhow::Result<Vec<Option<JumpDestTableWitness>>>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    let futures = block
        .transactions
        .as_transactions()
        .context("No transactions in block")?
        .iter()
        .zip(tx_traces)
        .map(|(tx, &tx_trace)| process_transaction(provider, tx, tx_trace))
        .collect::<FuturesOrdered<_>>();

    let vec_of_res = futures.collect::<Vec<_>>().await;
    vec_of_res.into_iter().collect::<Result<Vec<_>, _>>()
}

/// Processes the transaction with the given transaction hash and updates the
/// accounts state.
pub async fn process_transaction<ProviderT, TransportT>(
    provider: &ProviderT,
    tx: &Transaction,
    tx_trace: &BTreeMap<__compat_primitive_types::H160, TxnTrace>,
) -> anyhow::Result<Option<JumpDestTableWitness>>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    let tx_traces = tx_trace
        .iter()
        .map(|(h, t)| (Address::from(h.to_fixed_bytes()), t.clone()))
        .collect();

    let structlog_opt: Option<Vec<StructLog>> = get_normalized_structlog(provider, &tx.hash)
        .await
        .ok()
        .flatten();

    let jumpdest_table: Option<JumpDestTableWitness> = structlog_opt.and_then(|struct_log| {
        jumpdest::generate_jumpdest_table(tx, &struct_log, &tx_traces).map_or_else(
            |error| {
                info!(
                    "{:#?}: JumpDestTable generation failed with reason: {}",
                    tx.hash, error
                );
                None
            },
            |jdt| {
                info!(
                    "{:#?}: JumpDestTable generation succeeded with result: {}",
                    tx.hash, jdt
                );
                Some(jdt)
            },
        )
    });

    Ok(jumpdest_table)
}
