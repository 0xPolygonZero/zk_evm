use std::{
    collections::{HashMap, HashSet},
    sync::OnceLock,
};

use __compat_primitive_types::{H256, U256};
use alloy::{
    primitives::{keccak256, Address, B256, U160},
    providers::{
        ext::DebugApi as _,
        network::{eip2718::Encodable2718, Ethereum, Network},
        Provider,
    },
    rpc::types::{
        eth::{AccessList, Block, Transaction},
        trace::geth::{
            AccountState, DefaultFrame, DiffMode, GethDebugBuiltInTracerType, GethDebugTracerType,
            GethDebugTracingOptions, GethDefaultTracingOptions, GethTrace, PreStateConfig,
            PreStateFrame, PreStateMode,
        },
    },
    transports::Transport,
};
use anyhow::Context as _;
use evm_arithmetization::{CodeDb, JumpDestTableWitness};
use futures::stream::{FuturesOrdered, TryStreamExt};
use trace_decoder::{ContractCodeUsage, TxnInfo, TxnMeta, TxnTrace};

use crate::Compat;

/// Provides a way to check in constant time if an address points to a precompile.
fn precompiles() -> &'static HashSet<Address> {
    static PRECOMPILES: OnceLock<HashSet<Address>> = OnceLock::new();
    PRECOMPILES
        .get_or_init(|| HashSet::<Address>::from_iter((0..9).map(|x| Address::from(U160::from(x)))))
}

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
        .map(|tx| process_transaction(provider, tx))
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
    let (tx_receipt, pre_trace, diff_trace, structlog_trace) =
        fetch_tx_data(provider, &tx.hash).await?;

    let tx_receipt = tx_receipt.map_inner(rlp::map_receipt_envelope);
    let access_list = parse_access_list(tx.access_list.as_ref());

    let (code_db, tx_traces) = match (pre_trace, diff_trace) {
        (
            GethTrace::PreStateTracer(PreStateFrame::Default(read)),
            GethTrace::PreStateTracer(PreStateFrame::Diff(diff)),
        ) => process_tx_traces(access_list, read, diff).await?,
        _ => unreachable!(),
    };

    let jumpdest_table: JumpDestTableWitness =
        if let GethTrace::Default(structlog_frame) = structlog_trace {
            generate_jumpdest_table(tx, &structlog_frame, &tx_traces).await?
        } else {
            unreachable!()
        };

    let tx_meta = TxnMeta {
        byte_code: <Ethereum as Network>::TxEnvelope::try_from(tx.clone())?.encoded_2718(),
        new_txn_trie_node_byte: vec![],
        new_receipt_trie_node_byte: alloy::rlp::encode(tx_receipt.inner),
        gas_used: tx_receipt.gas_used as u64,
        jumpdest_table,
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
) -> anyhow::Result<
    (
        <Ethereum as Network>::ReceiptResponse,
        GethTrace,
        GethTrace,
        GethTrace,
    ),
    anyhow::Error,
>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    let tx_receipt_fut = provider.get_transaction_receipt(*tx_hash);
    let pre_trace_fut = provider.debug_trace_transaction(*tx_hash, prestate_tracing_options(false));
    let diff_trace_fut = provider.debug_trace_transaction(*tx_hash, prestate_tracing_options(true));
    let structlog_trace_fut =
        provider.debug_trace_transaction(*tx_hash, structlog_tracing_options());

    let (tx_receipt, pre_trace, diff_trace, structlog_trace) = futures::try_join!(
        tx_receipt_fut,
        pre_trace_fut,
        diff_trace_fut,
        structlog_trace_fut
    )?;

    Ok((
        tx_receipt.context("Transaction receipt not found.")?,
        pre_trace,
        diff_trace,
        structlog_trace,
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
            // Q: doesn't this remove the address from warm addresses?
            access_list.remove(&address).unwrap_or_default(),
            read_state,
            post_state,
            pre_state,
        );
        let code = process_code(post_state, read_state, &mut code_db).await;
        let nonce = process_nonce(post_state, &code);

        let result = TxnTrace {
            balance,
            nonce,
            storage_read,
            storage_written,
            code_usage: code,
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
            Some(ContractCodeUsage::Write(post_code.to_vec()))
        }
        (_, Some(read_code)) => {
            let code_hash = keccak256(read_code).compat();
            code_db.insert(code_hash, read_code.to_vec());
            Some(ContractCodeUsage::Read(code_hash))
        }
        _ => None,
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

/// Tracing options for the debug_traceTransaction call used for filling
/// JumpDest tables.
fn structlog_tracing_options() -> GethDebugTracingOptions {
    GethDebugTracingOptions {
        config: GethDefaultTracingOptions {
            disable_stack: Some(false),
            disable_memory: Some(true),
            disable_storage: Some(true),
            ..GethDefaultTracingOptions::default()
        },
        tracer: None,
        ..GethDebugTracingOptions::default()
    }
}

async fn generate_jumpdest_table(
    tx: &Transaction,
    structlog_trace: &DefaultFrame,
    tx_traces: &HashMap<Address, TxnTrace>,
) -> anyhow::Result<JumpDestTableWitness> {
    let mut jumpdest_table = JumpDestTableWitness::default();

    if structlog_trace.struct_logs.is_empty() {
        return Ok(jumpdest_table);
    };

    let callee_addr_to_code_hash: HashMap<Address, H256> = tx_traces
        .iter()
        .map(|(callee_addr, trace)| (callee_addr, &trace.code_usage))
        .filter(|(_callee_addr, code_usage)| code_usage.is_some())
        .map(|(callee_addr, code_usage)| {
            (*callee_addr, code_usage.as_ref().unwrap().get_code_hash())
        })
        .collect();

    let to_address: Address = tx
        .to
        .unwrap_or_else(|| panic!("No `to`-address for tx: {}.", tx.hash));

    // Guard against transactions to a non-contract address.
    if !callee_addr_to_code_hash.contains_key(&to_address) {
        return Ok(jumpdest_table);
    }
    let entrypoint_code_hash: H256 = callee_addr_to_code_hash[&to_address];

    // The next available context. Starts at 1. Never decrements.
    let mut next_ctx_available = 1;
    // Immediately use context 1;
    let mut call_stack = vec![(entrypoint_code_hash, next_ctx_available)];
    next_ctx_available += 1;

    for entry in structlog_trace.struct_logs.iter() {
        debug_assert!(entry.depth as usize <= next_ctx_available);
        log::debug!("{}", entry.op.as_str());
        match entry.op.as_str() {
            "CALL" | "CALLCODE" | "DELEGATECALL" | "STATICCALL" => {
                let callee_address = {
                    // This is the same stack index (i.e. 2nd) for all four opcodes.  See https://ethervm.io/#F1
                    let callee_raw = *entry
                        .stack
                        .as_ref()
                        .expect("No stack found in structLog.")
                        .iter()
                        .rev()
                        .nth(1)
                        .expect("Stack must contain at least two values for a CALL instruction.");
                    let lower_bytes = U160::from(callee_raw);
                    Address::from(lower_bytes)
                };

                if precompiles().contains(&callee_address) {
                    log::debug!("PRECOMPILE at address {} called.", &callee_address);
                } else if callee_addr_to_code_hash.contains_key(&callee_address) {
                    let code_hash = callee_addr_to_code_hash[&callee_address];
                    call_stack.push((code_hash, next_ctx_available));
                } else {
                    log::debug!(
                        "Callee address {} has no associated `code_hash`.  Please verify that this is not an EOA.",
                        &callee_address
                    );
                }
                next_ctx_available += 1;
            }
            "JUMPDEST" => {
                let (code_hash, ctx) = call_stack
                    .last()
                    .expect("Call stack was empty when a JUMPDEST was encountered.");
                jumpdest_table
                    .0
                    .entry(*code_hash)
                    .or_default()
                    .0
                    .entry(*ctx)
                    .or_default()
                    .insert(entry.pc as usize);
            }
            "EXTCODECOPY" | "EXTCODESIZE" => {
                next_ctx_available += 1;
            }
            "RETURN" => {
                call_stack.pop().expect("Call stack was empty at POP.");
            }
            _ => (),
        }
    }
    Ok(jumpdest_table)
}
