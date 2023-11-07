use std::io::Write;

use anyhow::{Context, Result};
use ethereum_types::{Address, Bloom, H256, U256};
use paladin::runtime::Runtime;
use plonky2_evm::proof::{BlockHashes, BlockMetadata};
use proof_protocol_decoder::{
    trace_protocol::{BlockTrace, BlockTraceTriePreImages, TxnInfo},
    types::{BlockLevelData, OtherBlockData},
};
use reqwest::{IntoUrl, Response};
use serde::Deserialize;
use thiserror::Error;
use tokio::try_join;
use tracing::{debug, info};

use crate::{config::MATIC_CHAIN_ID, prover_input::ProverInput};

#[derive(Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
enum JerigonResultItem {
    Result(TxnInfo),
    BlockWitness(BlockTraceTriePreImages),
}

/// The response from the `debug_traceBlockByNumber` RPC method.
#[derive(Deserialize, Debug)]
struct JerigonTraceResponse {
    result: Vec<JerigonResultItem>,
}

#[derive(Error, Debug)]
enum JerigonTraceError {
    #[error("expected BlockTraceTriePreImages in block_witness key")]
    BlockTraceTriePreImagesNotFound,
}

impl TryFrom<JerigonTraceResponse> for BlockTrace {
    type Error = JerigonTraceError;

    fn try_from(value: JerigonTraceResponse) -> Result<Self, Self::Error> {
        let mut txn_info = Vec::new();
        let mut trie_pre_images = None;

        for item in value.result {
            match item {
                JerigonResultItem::Result(info) => {
                    txn_info.push(info);
                }
                JerigonResultItem::BlockWitness(pre_images) => {
                    trie_pre_images = Some(pre_images);
                }
            }
        }

        let trie_pre_images =
            trie_pre_images.ok_or(JerigonTraceError::BlockTraceTriePreImagesNotFound)?;

        Ok(Self {
            txn_info,
            trie_pre_images,
        })
    }
}

impl JerigonTraceResponse {
    /// Fetches the block trace for the given block number.
    async fn fetch<U: IntoUrl>(rpc_url: U, block_number: u64) -> Result<Self> {
        let client = reqwest::Client::new();
        let block_number_hex = format!("0x{:x}", block_number);
        info!("Fetching block trace for block {}", block_number_hex);

        let response: Response = client
            .post(rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "debug_traceBlockByNumber",
                "params": [&block_number_hex, {"tracer": "zeroTracer"}],
                "id": 1,
            }))
            .send()
            .await
            .context("fetching debug_traceBlockByNumber")?;

        let bytes = response.bytes().await?;
        let des = &mut serde_json::Deserializer::from_slice(&bytes);
        let parsed: JerigonTraceResponse = serde_path_to_error::deserialize(des)
            .context("deserializing debug_traceBlockByNumber")?;

        Ok(parsed)
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct EthGetBlockByNumberResult {
    base_fee_per_gas: U256,
    difficulty: U256,
    gas_limit: U256,
    gas_used: U256,
    hash: H256,
    logs_bloom: Bloom,
    miner: Address,
    mix_hash: H256,
    number: U256,
    timestamp: U256,
}

/// The response from the `eth_getBlockByNumber` RPC method.
#[derive(Deserialize, Debug)]
struct EthGetBlockByNumberResponse {
    result: EthGetBlockByNumberResult,
}

impl From<EthGetBlockByNumberResponse> for OtherBlockData {
    fn from(value: EthGetBlockByNumberResponse) -> Self {
        let mut bloom = [U256::zero(); 8];

        for (i, word) in value
            .result
            .logs_bloom
            .as_fixed_bytes()
            .chunks_exact(32)
            .enumerate()
        {
            bloom[i] = U256::from_big_endian(word);
        }

        let block_metadata = BlockMetadata {
            block_beneficiary: value.result.miner,
            block_timestamp: value.result.timestamp,
            block_number: value.result.number,
            block_difficulty: value.result.difficulty,
            block_random: value.result.mix_hash,
            block_gaslimit: value.result.gas_limit,
            block_chain_id: MATIC_CHAIN_ID.into(),
            block_base_fee: value.result.base_fee_per_gas,
            block_gas_used: value.result.gas_used,
            block_bloom: bloom,
        };

        Self {
            b_data: BlockLevelData {
                b_meta: block_metadata,
                b_hashes: BlockHashes {
                    prev_hashes: Default::default(),
                    cur_hash: value.result.hash,
                },
            },
            genesis_state_trie_root: Default::default(),
        }
    }
}

impl EthGetBlockByNumberResponse {
    /// Fetches the block metadata for the given block number.
    async fn fetch<U: IntoUrl>(rpc_url: U, block_number: u64) -> Result<Self> {
        let client = reqwest::Client::new();
        let block_number_hex = format!("0x{:x}", block_number);
        info!("Fetching block metadata for block {}", block_number_hex);

        let response: Response = client
            .post(rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_getBlockByNumber",
                "params": [&block_number_hex, false],
                "id": 1,
            }))
            .send()
            .await
            .context("fetching eth_getBlockByNumber")?;

        let bytes = response.bytes().await?;
        let des = &mut serde_json::Deserializer::from_slice(&bytes);
        let parsed: EthGetBlockByNumberResponse =
            serde_path_to_error::deserialize(des).context("deserializing eth_getBlockByNumber")?;

        Ok(parsed)
    }
}

/// The main function for the jerigon mode.
pub(crate) async fn rpc_main(runtime: Runtime, rpc_url: &str, block_number: u64) -> Result<()> {
    let (trace_result, block_result) = try_join!(
        JerigonTraceResponse::fetch(rpc_url, block_number),
        EthGetBlockByNumberResponse::fetch(rpc_url, block_number)
    )?;

    debug!("Got block result: {:?}", block_result);
    debug!("Got trace result: {:?}", trace_result);

    let prover_input = ProverInput {
        block_trace: trace_result.try_into()?,
        other_data: block_result.into(),
    };

    let proof = prover_input.prove(&runtime).await?;
    std::io::stdout().write_all(&serde_json::to_vec(&proof.intern)?)?;

    Ok(())
}
