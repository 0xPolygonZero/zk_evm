use std::collections::{HashMap, HashSet};

use __compat_primitive_types::{H256, U256};
use alloy::{
    primitives::{keccak256, Address, B256},
    providers::{
        ext::DebugApi as _,
        network::{eip2718::Encodable2718, Ethereum, Network},
        Provider,
    },
    rpc::types::{
        eth::Transaction,
        eth::{AccessList, Block},
        trace::geth::{
            AccountState, DiffMode, GethDebugBuiltInTracerType, GethTrace, PreStateConfig,
            PreStateFrame, PreStateMode,
        },
        trace::geth::{GethDebugTracerType, GethDebugTracingOptions},
    },
    transports::Transport,
};
use anyhow::Context as _;
use futures::stream::{FuturesOrdered, TryStreamExt};
use trace_decoder::trace_protocol::{ContractCodeUsage, TxnInfo, TxnMeta, TxnTrace};

use super::CodeDb;
use crate::compat::Compat;

/// Processes the transactions in the given block and updates the code db.
pub(super) async fn process_transactions<ProviderT, TransportT>(
    block: &Block,
    provider: &ProviderT,
) -> anyhow::Result<(CodeDb, Vec<TxnInfo>)>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    block
        .transactions
        .as_transactions()
        .context("No transactions in block")?
        .iter()
        .map(|tx| super::txn::process_transaction(provider, tx))
        .collect::<FuturesOrdered<_>>()
        .try_fold(
            (HashMap::new(), Vec::new()),
            |(mut code_db, mut txn_infos), (tx_code_db, txn_info)| async move {
                code_db.extend(tx_code_db);
                txn_infos.push(txn_info);
                Ok((code_db, txn_infos))
            },
        )
        .await
}

/// Processes the transaction with the given transaction hash and updates the
/// accounts state.
async fn process_transaction<ProviderT, TransportT>(
    provider: &ProviderT,
    tx: &Transaction,
) -> anyhow::Result<(CodeDb, TxnInfo)>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    let (tx_receipt, pre_trace, diff_trace) = fetch_tx_data(provider, &tx.hash).await?;
    let tx_receipt = tx_receipt.map_inner(rlp::map_receipt_envelope);
    let access_list = parse_access_list(tx.access_list.as_ref());

    let tx_meta = TxnMeta {
        byte_code: <Ethereum as Network>::TxEnvelope::try_from(tx.clone())?.encoded_2718(),
        new_txn_trie_node_byte: vec![],
        new_receipt_trie_node_byte: alloy::rlp::encode(tx_receipt.inner),
        gas_used: tx_receipt.gas_used as u64,
    };

    let (code_db, tx_traces) = match (pre_trace, diff_trace) {
        (
            GethTrace::PreStateTracer(PreStateFrame::Default(read)),
            GethTrace::PreStateTracer(PreStateFrame::Diff(diff)),
        ) => process_tx_traces(access_list, read, diff).await?,
        _ => unreachable!(),
    };

    Ok((
        code_db,
        TxnInfo {
            meta: tx_meta,
            traces: tx_traces
                .into_iter()
                .map(|(k, v)| (k.compat(), v))
                .collect(),
        },
    ))
}

/// Fetches the transaction data for the given transaction hash.
async fn fetch_tx_data<ProviderT, TransportT>(
    provider: &ProviderT,
    tx_hash: &B256,
) -> anyhow::Result<(<Ethereum as Network>::ReceiptResponse, GethTrace, GethTrace), anyhow::Error>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    let tx_receipt_fut = provider.get_transaction_receipt(*tx_hash);
    let pre_trace_fut = provider.debug_trace_transaction(*tx_hash, prestate_tracing_options(false));
    let diff_trace_fut = provider.debug_trace_transaction(*tx_hash, prestate_tracing_options(true));

    let (tx_receipt, pre_trace, diff_trace) =
        futures::try_join!(tx_receipt_fut, pre_trace_fut, diff_trace_fut,)?;

    Ok((
        tx_receipt.context("Transaction receipt not found.")?,
        pre_trace,
        diff_trace,
    ))
}

/// Parse the access list data into a hashmap.
fn parse_access_list(access_list: Option<&AccessList>) -> HashMap<Address, HashSet<H256>> {
    let mut result = HashMap::new();

    if let Some(access_list) = access_list {
        for item in access_list.0.clone() {
            result
                .entry(item.address)
                .or_insert_with(HashSet::new)
                .extend(item.storage_keys.into_iter().map(Compat::compat));
        }
    }

    result
}

/// Processes the transaction traces and updates the accounts state.
async fn process_tx_traces(
    mut access_list: HashMap<Address, HashSet<H256>>,
    read_trace: PreStateMode,
    diff_trace: DiffMode,
) -> anyhow::Result<(CodeDb, HashMap<Address, TxnTrace>)> {
    let DiffMode {
        pre: pre_trace,
        post: post_trace,
    } = diff_trace;

    let addresses: HashSet<_> = read_trace
        .0
        .keys()
        .chain(post_trace.keys())
        .chain(pre_trace.keys())
        .chain(access_list.keys())
        .copied()
        .collect();

    let mut traces = HashMap::new();
    let mut code_db: CodeDb = HashMap::new();

    for address in addresses {
        let read_state = read_trace.0.get(&address);
        let pre_state = pre_trace.get(&address);
        let post_state = post_trace.get(&address);

        let balance = post_state.and_then(|x| x.balance.map(Compat::compat));
        let (storage_read, storage_written) = process_storage(
            access_list.remove(&address).unwrap_or_default(),
            read_state,
            post_state,
            pre_state,
        );
        let code = process_code(post_state, read_state, &mut code_db).await;
        let nonce = process_nonce(post_state, &code);
        let self_destructed = process_self_destruct(post_state, pre_state);

        let result = TxnTrace {
            balance,
            nonce,
            storage_read,
            storage_written,
            code_usage: code,
            self_destructed,
        };

        traces.insert(address, result);
    }

    Ok((code_db, traces))
}

/// Processes the nonce for the given account state.
///
/// If a contract is created, the nonce is set to 1.
fn process_nonce(
    post_state: Option<&AccountState>,
    code_usage: &Option<ContractCodeUsage>,
) -> Option<U256> {
    post_state
        .and_then(|x| x.nonce.map(Into::into))
        .or_else(|| {
            if let Some(ContractCodeUsage::Write(_)) = code_usage.as_ref() {
                Some(U256::from(1))
            } else {
                None
            }
        })
}

/// Processes the storage for the given account state.
///
/// Returns the storage read and written for the given account in the
/// transaction and updates the storage keys.
fn process_storage(
    access_list: HashSet<__compat_primitive_types::H256>,
    acct_state: Option<&AccountState>,
    post_acct: Option<&AccountState>,
    pre_acct: Option<&AccountState>,
) -> (Option<Vec<H256>>, Option<HashMap<H256, U256>>) {
    let mut storage_read = access_list;
    storage_read.extend(
        acct_state
            .map(|acct| {
                acct.storage
                    .keys()
                    .copied()
                    .map(Compat::compat)
                    .collect::<Vec<H256>>()
            })
            .unwrap_or_default(),
    );

    let mut storage_written: HashMap<H256, U256> = post_acct
        .map(|x| {
            x.storage
                .iter()
                .map(|(k, v)| ((*k).compat(), U256::from_big_endian(&v.0)))
                .collect()
        })
        .unwrap_or_default();

    // Add the deleted keys to the storage written
    if let Some(pre_acct) = pre_acct {
        for key in pre_acct.storage.keys() {
            storage_written
                .entry((*key).compat())
                .or_insert(U256::zero());
        }
    };

    (
        Option::from(storage_read.into_iter().collect::<Vec<H256>>()).filter(|v| !v.is_empty()),
        Option::from(storage_written).filter(|v| !v.is_empty()),
    )
}

/// Processes the code usage for the given account state.
async fn process_code(
    post_state: Option<&AccountState>,
    read_state: Option<&AccountState>,
    code_db: &mut CodeDb,
) -> Option<ContractCodeUsage> {
    match (
        post_state.and_then(|x| x.code.as_ref()),
        read_state.and_then(|x| x.code.as_ref()),
    ) {
        (Some(post_code), _) => {
            let code_hash = keccak256(post_code).compat();
            code_db.insert(code_hash, post_code.to_vec());
            Some(ContractCodeUsage::Write(post_code.to_vec().into()))
        }
        (_, Some(read_code)) => {
            let code_hash = keccak256(read_code).compat();
            code_db.insert(code_hash, read_code.to_vec());

            Some(ContractCodeUsage::Read(code_hash))
        }
        _ => None,
    }
}

/// Processes the self destruct for the given account state.
fn process_self_destruct(
    post_state: Option<&AccountState>,
    pre_state: Option<&AccountState>,
) -> Option<bool> {
    if post_state.is_none() && pre_state.is_some() {
        Some(true)
    } else {
        None
    }
}

mod rlp {
    use alloy::consensus::{Receipt, ReceiptEnvelope};
    use alloy::rpc::types::eth::ReceiptWithBloom;

    pub fn map_receipt_envelope(
        rpc: ReceiptEnvelope<alloy::rpc::types::eth::Log>,
    ) -> ReceiptEnvelope<alloy::primitives::Log> {
        match rpc {
            ReceiptEnvelope::Legacy(it) => ReceiptEnvelope::Legacy(map_receipt_with_bloom(it)),
            ReceiptEnvelope::Eip2930(it) => ReceiptEnvelope::Eip2930(map_receipt_with_bloom(it)),
            ReceiptEnvelope::Eip1559(it) => ReceiptEnvelope::Eip1559(map_receipt_with_bloom(it)),
            ReceiptEnvelope::Eip4844(it) => ReceiptEnvelope::Eip4844(map_receipt_with_bloom(it)),
            other => panic!("unsupported receipt type: {:?}", other),
        }
    }
    fn map_receipt_with_bloom(
        rpc: ReceiptWithBloom<alloy::rpc::types::eth::Log>,
    ) -> ReceiptWithBloom<alloy::primitives::Log> {
        let ReceiptWithBloom {
            receipt:
                Receipt {
                    status,
                    cumulative_gas_used,
                    logs,
                },
            logs_bloom,
        } = rpc;
        ReceiptWithBloom {
            receipt: Receipt {
                status,
                cumulative_gas_used,
                logs: logs.into_iter().map(|it| it.inner).collect(),
            },
            logs_bloom,
        }
    }
}

/// Tracing options for the debug_traceTransaction call.
fn prestate_tracing_options(diff_mode: bool) -> GethDebugTracingOptions {
    GethDebugTracingOptions {
        tracer_config: PreStateConfig {
            diff_mode: Some(diff_mode),
        }
        .into(),
        tracer: Some(GethDebugTracerType::BuiltInTracer(
            GethDebugBuiltInTracerType::PreStateTracer,
        )),
        ..GethDebugTracingOptions::default()
    }
}
