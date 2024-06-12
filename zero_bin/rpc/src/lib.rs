use alloy::primitives::B256;
use alloy::rpc::types::eth::BlockNumberOrTag;
use alloy::{
    providers::Provider,
    rpc::types::eth::{Block, BlockId, Withdrawal},
    transports::Transport,
};
use anyhow::Context as _;
use common::block_interval::BlockInterval;
use evm_arithmetization::proof::{BlockHashes, BlockMetadata};
use futures::{StreamExt as _, TryStreamExt as _};
use prover::{BlockProverInput, ProverInput};
use serde::Deserialize;
use serde_json::json;
use trace_decoder::{
    trace_protocol::{
        BlockTrace, BlockTraceTriePreImages, CombinedPreImages, TrieCompact, TxnInfo,
    },
    types::{BlockLevelData, OtherBlockData},
};

/// Transaction traces retrieved from Erigon zeroTracer.
#[derive(Debug, Deserialize)]
pub struct ZeroTxResult {
    #[serde(rename(deserialize = "txHash"))]
    pub tx_hash: alloy::primitives::TxHash,
    pub result: TxnInfo,
}

/// Block witness retrieved from Erigon zeroTracer.
#[derive(Debug, Deserialize)]
pub struct ZeroBlockWitness(TrieCompact);

/// When [fetching a block over RPC](https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_getblockbynumber),
/// we can choose the transaction format, between:
/// - Full JSON.
/// - Just the hash.
///
/// We only need the latter.
const BLOCK_WITH_FULL_TRANSACTIONS: bool = false;

/// Retrieve block information from the provider
pub async fn get_block<ProviderT, TransportT>(
    provider: &mut ProviderT,
    target_block_id: BlockId,
    full_transaction_data: bool,
) -> anyhow::Result<Block>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    provider
        .get_block(target_block_id, full_transaction_data)
        .await?
        .context("block does not exist")
}

pub async fn block_prover_input<ProviderT, TransportT>(
    provider: ProviderT,
    target_block_id: BlockId,
    checkpoint_state_trie_root: B256,
) -> anyhow::Result<BlockProverInput>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    // Grab trace information
    let tx_results = provider
        .raw_request::<_, Vec<ZeroTxResult>>(
            "debug_traceBlockByNumber".into(),
            (target_block_id, json!({"tracer": "zeroTracer"})),
        )
        .await?;

    // Grab block witness info (packed as combined trie pre-images)
    let block_witness = provider
        .raw_request::<_, ZeroBlockWitness>("eth_getWitness".into(), vec![target_block_id])
        .await?;

    // Grab block info
    let target_block = provider
        .get_block(target_block_id, BLOCK_WITH_FULL_TRANSACTIONS)
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
                        .get_block(n.into(), BLOCK_WITH_FULL_TRANSACTIONS)
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
    Ok(BlockProverInput {
        block_trace: BlockTrace {
            trie_pre_images: BlockTraceTriePreImages::Combined(CombinedPreImages {
                compact: block_witness.0,
            }),
            txn_info: tx_results.into_iter().map(|it| it.result).collect(),
            code_db: Default::default(),
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

/// Obtain the prover input for a given block interval
pub async fn prover_input<ProviderT, TransportT>(
    mut provider: ProviderT,
    block_interval: BlockInterval,
    checkpoint_block_id: BlockId,
) -> anyhow::Result<ProverInput>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    // Grab interval checkpoint block state trie
    let checkpoint_state_trie_root = get_block(
        &mut provider,
        checkpoint_block_id,
        BLOCK_WITH_FULL_TRANSACTIONS,
    )
    .await?
    .header
    .state_root;

    let mut block_proofs = Vec::new();
    let mut block_interval = block_interval.into_bounded_stream()?;

    while let Some(block_num) = block_interval.next().await {
        let block_id = BlockId::Number(BlockNumberOrTag::Number(block_num));
        let block_prover_input =
            block_prover_input(&provider, block_id, checkpoint_state_trie_root).await?;
        block_proofs.push(block_prover_input);
    }
    Ok(ProverInput {
        blocks: block_proofs,
    })
}

trait Compat<Out> {
    fn compat(self) -> Out;
}

impl Compat<__compat_primitive_types::H160> for alloy::primitives::Address {
    fn compat(self) -> __compat_primitive_types::H160 {
        let alloy::primitives::Address(alloy::primitives::FixedBytes(arr)) = self;
        __compat_primitive_types::H160(arr)
    }
}

impl Compat<__compat_primitive_types::H256> for alloy::primitives::B256 {
    fn compat(self) -> __compat_primitive_types::H256 {
        let alloy::primitives::FixedBytes(arr) = self;
        __compat_primitive_types::H256(arr)
    }
}

impl Compat<[__compat_primitive_types::U256; 8]> for alloy::primitives::Bloom {
    fn compat(self) -> [__compat_primitive_types::U256; 8] {
        let alloy::primitives::Bloom(alloy::primitives::FixedBytes(src)) = self;
        // have      u8 * 256
        // want    U256 * 8
        // (no unsafe, no unstable)
        let mut chunks = src.chunks_exact(32);
        let dst = core::array::from_fn(|_ix| {
            // This is a bit spicy because we're going from an uninterpeted array of bytes
            // to wide integers, but we trust this `From` impl to do the right thing
            __compat_primitive_types::U256::from(
                <[u8; 32]>::try_from(chunks.next().unwrap()).unwrap(),
            )
        });
        assert_eq!(chunks.len(), 0);
        dst
    }
}

#[test]
fn bloom() {
    let _did_not_panic = alloy::primitives::Bloom::ZERO.compat();
}
