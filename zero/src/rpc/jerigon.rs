use core::iter::Iterator;
use std::ops::Deref as _;
use std::time::Duration;

use alloy::eips::BlockNumberOrTag;
use alloy::{
    providers::Provider,
    rpc::types::{eth::BlockId, Block, BlockTransactionsKind},
    transports::Transport,
};
use anyhow::Context as _;
use compat::Compat;
use evm_arithmetization::jumpdest::JumpDestTableWitness;
use serde::Deserialize;
use serde_json::json;
use trace_decoder::{BlockTrace, BlockTraceTriePreImages, CombinedPreImages, TxnInfo};
use tracing::{debug, warn};

use super::{fetch_other_block_data, JumpdestSrc};
use crate::prover::BlockProverInput;
use crate::provider::CachedProvider;
use crate::rpc::jumpdest::{generate_jumpdest_table, get_block_normalized_structlogs};

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
    jumpdest_src: JumpdestSrc,
    fetch_timeout: Duration,
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

    let block_jumpdest_table_witnesses: Vec<Option<JumpDestTableWitness>> = match jumpdest_src {
        JumpdestSrc::ProverSimulation => vec![None; tx_results.len()],
        JumpdestSrc::ClientFetchedStructlogs => {
            // In case of the error with retrieving structlogs from the server,
            // continue without interruption. Equivalent to `ProverSimulation` case.
            process_transactions(
                &block,
                cached_provider.get_provider().await?.deref(),
                &tx_results,
                &fetch_timeout,
            )
            .await
            .unwrap_or_else(|e| {
                warn!("failed to fetch server structlogs for block {target_block_id}: {e}");
                vec![None; tx_results.len()]
            })
        }
        JumpdestSrc::Serverside => todo!(),
    };

    // weave in the JDTs
    let txn_info = tx_results
        .into_iter()
        .zip(block_jumpdest_table_witnesses)
        .map(|(mut tx_info, jdtw)| {
            tx_info.meta.jumpdest_table = jdtw;
            tx_info
        })
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

/// Processes the transactions in the given block, generating jumpdest tables
/// and updates the code database
pub async fn process_transactions<'i, ProviderT, TransportT>(
    block: &Block,
    provider: &ProviderT,
    tx_results: &[TxnInfo],
    fetch_timeout: &Duration,
) -> anyhow::Result<Vec<Option<JumpDestTableWitness>>>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    let block_structlogs = get_block_normalized_structlogs(
        provider,
        &BlockNumberOrTag::from(block.header.number),
        fetch_timeout,
    )
    .await?;

    let tx_traces = tx_results
        .iter()
        .map(|tx| tx.traces.iter().map(|(h, t)| (h.compat(), t)));

    let block_jumpdest_tables = block
        .transactions
        .as_transactions()
        .context("no transactions in block")?
        .iter()
        .zip(block_structlogs)
        .zip(tx_traces)
        .map(|((tx, structlog), tx_trace)| {
            structlog.and_then(|it| {
                generate_jumpdest_table(tx, &it.1, tx_trace).map_or_else(
                    |error| {
                        debug!(
                            "{}: JumpDestTable generation failed with reason: {:?}",
                            tx.hash.to_string(),
                            error
                        );
                        None
                    },
                    Some,
                )
            })
        })
        .collect::<Vec<_>>();

    Ok(block_jumpdest_tables)
}
