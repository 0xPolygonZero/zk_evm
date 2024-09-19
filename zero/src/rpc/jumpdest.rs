use core::default::Default;
use core::option::Option::None;
use core::time::Duration;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::ops::Not as _;
use std::sync::OnceLock;

use __compat_primitive_types::H256;
use alloy::primitives::Address;
use alloy::primitives::U160;
use alloy::providers::ext::DebugApi;
use alloy::providers::Provider;
use alloy::rpc::types::eth::Transaction;
use alloy::rpc::types::trace::geth::StructLog;
use alloy::rpc::types::trace::geth::{GethDebugTracingOptions, GethDefaultTracingOptions};
use alloy::transports::RpcError;
use alloy::transports::Transport;
use alloy::transports::TransportErrorKind;
use alloy_primitives::B256;
use alloy_primitives::U256;
use anyhow::ensure;
use evm_arithmetization::jumpdest::JumpDestTableWitness;
use keccak_hash::keccak;
use structlogprime::normalize_structlog;
use tokio::time::timeout;
use trace_decoder::TxnTrace;
use tracing::trace;

/// The maximum time we are willing to wait for a structlog before failing over
/// to simulating the JumpDest analysis.
const TIMEOUT_LIMIT: Duration = Duration::from_secs(10);

/// Structure of Etheruem memory
type Word = [u8; 32];
const WORDSIZE: usize = std::mem::size_of::<Word>();

/// Pass `true` for the components needed.
fn structlog_tracing_options(stack: bool, memory: bool, storage: bool) -> GethDebugTracingOptions {
    GethDebugTracingOptions {
        config: GethDefaultTracingOptions {
            disable_stack: Some(!stack),
            // needed for CREATE2
            disable_memory: Some(!memory),
            disable_storage: Some(!storage),
            ..GethDefaultTracingOptions::default()
        },
        tracer: None,
        ..GethDebugTracingOptions::default()
    }
}

fn trace_contains_create2(structlog: Vec<StructLog>) -> bool {
    structlog.iter().any(|entry| entry.op == "CREATE2")
}

// Gets the lightest possible structlog for transcation `tx_hash`.
pub(crate) async fn get_normalized_structlog<ProviderT, TransportT>(
    provider: &ProviderT,
    tx_hash: &B256,
) -> Result<Option<Vec<StructLog>>, RpcError<TransportErrorKind>>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    // Optimization: It may be a better default to pull the stack immediately.
    let light_structlog_trace = provider
        .debug_trace_transaction(*tx_hash, structlog_tracing_options(false, false, false))
        .await?;

    let structlogs_opt: Option<Vec<StructLog>> = normalize_structlog(light_structlog_trace).await;

    let need_memory = structlogs_opt.is_some_and(trace_contains_create2);
    trace!("Need structlog with memory: {need_memory}");

    let structlog = provider.debug_trace_transaction(
        *tx_hash,
        structlog_tracing_options(true, need_memory, false),
    );

    match timeout(TIMEOUT_LIMIT, structlog).await {
        Err(ellapsed_error) => Err(RpcError::Transport(TransportErrorKind::Custom(Box::new(
            ellapsed_error,
        )))),
        Ok(structlog_res) => Ok(normalize_structlog(structlog_res?).await),
    }
}

/// Provides a way to check in constant time if an address points to a
/// precompile.
fn precompiles() -> &'static HashSet<Address> {
    static PRECOMPILES: OnceLock<HashSet<Address>> = OnceLock::new();
    PRECOMPILES.get_or_init(|| {
        HashSet::<Address>::from_iter((1..=0xa).map(|x| Address::from(U160::from(x))))
    })
}

/// Generate at JUMPDEST table by simulating the call stack in EVM,
/// using a Geth structlog as input.
pub(crate) fn generate_jumpdest_table(
    tx: &Transaction,
    struct_log: &[StructLog],
    tx_traces: &BTreeMap<Address, TxnTrace>,
) -> anyhow::Result<JumpDestTableWitness> {
    trace!("Generating JUMPDEST table for tx: {}", tx.hash);

    let mut jumpdest_table = JumpDestTableWitness::default();

    // This does not contain `initcodes`.
    let callee_addr_to_code_hash: HashMap<Address, H256> = tx_traces
        .iter()
        .map(|(callee_addr, trace)| (callee_addr, &trace.code_usage))
        .filter(|(_callee_addr, code_usage)| code_usage.is_some())
        .map(|(callee_addr, code_usage)| {
            (*callee_addr, code_usage.as_ref().unwrap().get_code_hash())
        })
        .collect();

    trace!(
        "Transaction: {} is a {}.",
        tx.hash,
        if tx.to.is_some() {
            "message call"
        } else {
            "contract creation"
        }
    );

    let entrypoint_code_hash: H256 = match tx.to {
        Some(to_address) if precompiles().contains(&to_address) => return Ok(jumpdest_table),
        Some(to_address) if callee_addr_to_code_hash.contains_key(&to_address).not() => {
            return Ok(jumpdest_table)
        }
        Some(to_address) => callee_addr_to_code_hash[&to_address],
        None => {
            let init = &tx.input;
            keccak(init)
        }
    };

    // `None` encodes that previous `entry` was not a JUMP or JUMPI with true
    // condition, `Some(jump_target)` encodes we came from a JUMP or JUMPI with
    // true condition and target `jump_target`.
    let mut prev_jump: Option<U256> = None;

    // Call depth of the previous `entry`. We initialize to 0 as this compares
    // smaller to 1.
    //let mut prev_depth = 0;
    // The next available context. Starts at 1. Never decrements.
    let mut next_ctx_available = 1;
    // Immediately use context 1;
    let mut call_stack = vec![(entrypoint_code_hash, next_ctx_available)];
    next_ctx_available += 1;

    for (step, entry) in struct_log.iter().enumerate() {
        let op = entry.op.as_str();
        let curr_depth: usize = entry.depth.try_into().unwrap();

        ensure!(curr_depth <= next_ctx_available, "Structlog is malformed.");

        while curr_depth < call_stack.len() {
            call_stack.pop();
        }

        ensure!(call_stack.is_empty().not(), "Call stack was empty.");
        let (code_hash, ctx) = call_stack.last().unwrap();

        trace!("TX:   {:?}", tx.hash);
        trace!("STEP: {:?}", step);
        trace!("STEPS: {:?}", struct_log.len());
        trace!("OPCODE: {}", entry.op.as_str());
        trace!("CODE: {:?}", code_hash);
        trace!("CTX:  {:?}", ctx);
        trace!("CURR_DEPTH:  {:?}", curr_depth);
        trace!("{:#?}\n", entry);

        match op {
            "CALL" | "CALLCODE" | "DELEGATECALL" | "STATICCALL" => {
                ensure!(entry.stack.as_ref().is_some(), "No evm stack found.");
                // We reverse the stack, so the order matches our assembly code.
                let evm_stack: Vec<_> = entry.stack.as_ref().unwrap().iter().rev().collect();
                let operands = 2; // actually 6 or 7.
                ensure!(
                    evm_stack.len() >= operands,
                    "Opcode {op} expected {operands} operands at the EVM stack, but only {} were found.",
                    evm_stack.len()
                );
                // This is the same stack index (i.e. 2nd) for all four opcodes. See https://ethervm.io/#F1
                let [_gas, address, ..] = evm_stack[..] else {
                    unreachable!()
                };

                let callee_address = {
                    // Clear the upper half of the operand.
                    let callee_raw = *address;
                    // let (callee_raw, _overflow) = callee_raw.overflowing_shl(128);
                    // let (callee_raw, _overflow) = callee_raw.overflowing_shr(128);

                    ensure!(callee_raw <= U256::from(U160::MAX));
                    let lower_20_bytes = U160::from(callee_raw);
                    Address::from(lower_20_bytes)
                };

                if precompiles().contains(&callee_address) {
                    trace!("Called precompile at address {}.", &callee_address);
                } else if callee_addr_to_code_hash.contains_key(&callee_address) {
                    let code_hash = callee_addr_to_code_hash[&callee_address];
                    call_stack.push((code_hash, next_ctx_available));
                } else {
                    // This case happens if calling an EOA. This is described
                    // under opcode `STOP`: https://www.evm.codes/#00?fork=cancun
                    trace!(
                        "Callee address {} has no associated `code_hash`.",
                        &callee_address
                    );
                }
                next_ctx_available += 1;
                prev_jump = None;
            }
            "CREATE" => {
                ensure!(entry.stack.as_ref().is_some(), "No evm stack found.");
                // We reverse the stack, so the order matches our assembly code.
                let evm_stack: Vec<_> = entry.stack.as_ref().unwrap().iter().rev().collect();
                let operands = 3;
                ensure!(
                    evm_stack.len() >= operands,
                    "Opcode {op} expected {operands} operands at the EVM stack, but only {} were found.",
                    evm_stack.len()
                );
                let [_value, _offset, _size, ..] = evm_stack[..] else {
                    unreachable!()
                };

                let contract_address = tx.from.create(tx.nonce);
                ensure!(callee_addr_to_code_hash.contains_key(&contract_address));
                let code_hash = callee_addr_to_code_hash[&contract_address];
                call_stack.push((code_hash, next_ctx_available));

                next_ctx_available += 1;
                prev_jump = None;
            }
            "CREATE2" => {
                ensure!(entry.stack.as_ref().is_some(), "No evm stack found.");
                // We reverse the stack, so the order matches our assembly code.
                let evm_stack: Vec<_> = entry.stack.as_ref().unwrap().iter().rev().collect();
                let operands = 4;
                ensure!(
                    evm_stack.len() >= operands,
                    "Opcode {op} expected {operands} operands at the EVM stack, but only {} were found.",
                    evm_stack.len()
                );
                let [_value, offset, size, _salt, ..] = evm_stack[..] else {
                    unreachable!()
                };
                ensure!(*offset <= U256::from(usize::MAX));
                let offset: usize = offset.to();
                ensure!(*size <= U256::from(usize::MAX));

                let size: usize = size.to();
                let memory_size = entry.memory.as_ref().unwrap().len() * WORDSIZE;
                // let salt: Word = salt.to_be_bytes();

                ensure!(
                    entry.memory.is_some() && offset + size <= memory_size,
                    "Insufficient memory available for {op}. Contract has size {size} and is supposed to be stored between offset {offset} and {}, but memory size is only {memory_size}.", offset+size
                );
                let memory_raw: &[String] = entry.memory.as_ref().unwrap();
                let memory_parsed: Vec<anyhow::Result<Word>> = memory_raw
                    .iter()
                    .map(|s| {
                        // let c = s.parse();
                        let c = U256::from_str_radix(s, 16);
                        ensure!(c.is_ok(), "Parsing memory failed.");
                        let a: U256 = c.unwrap();
                        let d: Word = a.to_be_bytes();
                        Ok(d)
                    })
                    .collect();
                let mem_res: anyhow::Result<Vec<Word>> = memory_parsed.into_iter().collect();
                let memory: Vec<u8> = mem_res?.concat();

                let init_code = &memory[offset..offset + size];
                let init_code_hash = keccak(init_code);
                // let contract_address = tx.from.create2_from_code(salt, init_code);
                // ensure!(callee_addr_to_code_hash.contains_key(&contract_address));
                // let code_hash = callee_addr_to_code_hash[&contract_address];
                call_stack.push((init_code_hash, next_ctx_available));

                next_ctx_available += 1;
                prev_jump = None;
            }
            "JUMP" => {
                ensure!(entry.stack.as_ref().is_some(), "No evm stack found.");
                // We reverse the stack, so the order matches our assembly code.
                let evm_stack: Vec<_> = entry.stack.as_ref().unwrap().iter().rev().collect();
                let operands = 1;
                ensure!(
                    evm_stack.len() >= operands,
                    "Opcode {op} expected {operands} operands at the EVM stack, but only {} were found.",
                    evm_stack.len()
                );
                let [jump_target, ..] = evm_stack[..] else {
                    unreachable!()
                };
                // ensure!(
                //     *counter <= U256::from(u64::MAX),
                //     "Operand for {op} caused overflow:  counter: {} is larger than u64::MAX
                // {}",     *counter,
                //     u64::MAX
                // );
                // let jump_target: u64 = counter.to();

                prev_jump = Some(*jump_target);
            }
            "JUMPI" => {
                ensure!(entry.stack.as_ref().is_some(), "No evm stack found.");
                // We reverse the stack, so the order matches our assembly code.
                let evm_stack: Vec<_> = entry.stack.as_ref().unwrap().iter().rev().collect();
                let operands = 2;
                ensure!(
                    evm_stack.len() >= operands,
                    "Opcode {op} expected {operands} operands at the EVM stack, but only {} were found.",
                    evm_stack.len()
                );
                let [jump_target, condition, ..] = evm_stack[..] else {
                    unreachable!()
                };
                // ensure!(
                //     *counter <= U256::from(u64::MAX),
                //     "Operand for {op} caused overflow:  counter: {} is larger than u64::MAX
                // {}",     *counter,
                //     u64::MAX
                // );
                // let jump_target: u64 = counter.to();
                let jump_condition = condition.is_zero().not();

                prev_jump = if jump_condition {
                    Some(*jump_target)
                } else {
                    None
                };
            }
            "JUMPDEST" => {
                let jumped_here = if let Some(jmp_target) = prev_jump {
                    jmp_target == U256::from(entry.pc)
                } else {
                    false
                };
                let jumpdest_offset = entry.pc as usize;
                if jumped_here {
                    jumpdest_table.insert(*code_hash, *ctx, jumpdest_offset);
                }
                // else: we do not care about JUMPDESTs reached through fall-through.
                prev_jump = None;
            }
            "EXTCODECOPY" | "EXTCODESIZE" => {
                next_ctx_available += 1;
                prev_jump = None;
            }
            _ => {
                prev_jump = None;
            }
        }
    }
    Ok(jumpdest_table)
}

pub mod structlogprime {
    use core::option::Option::None;
    use std::collections::BTreeMap;

    use alloy::rpc::types::trace::geth::{DefaultFrame, GethTrace, StructLog};
    use alloy_primitives::{Bytes, B256, U256};
    use serde::{ser::SerializeMap as _, Deserialize, Serialize, Serializer};
    use serde_json::Value;

    /// Geth Default struct log trace frame
    ///
    /// <https://github.com/ethereum/go-ethereum/blob/a9ef135e2dd53682d106c6a2aede9187026cc1de/eth/tracers/logger/logger.go#L406-L411>
    #[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct DefaultFramePrime {
        /// Whether the transaction failed
        pub failed: bool,
        /// How much gas was used.
        pub gas: u64,
        /// Output of the transaction
        #[serde(serialize_with = "alloy_serde::serialize_hex_string_no_prefix")]
        pub return_value: Bytes,
        /// Recorded traces of the transaction
        pub struct_logs: Vec<StructLogPrime>,
    }

    /// Represents a struct log entry in a trace
    ///
    /// <https://github.com/ethereum/go-ethereum/blob/366d2169fbc0e0f803b68c042b77b6b480836dbc/eth/tracers/logger/logger.go#L413-L426>
    #[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
    pub(crate) struct StructLogPrime {
        /// Program counter
        pub pc: u64,
        /// Opcode to be executed
        pub op: String,
        /// Remaining gas
        pub gas: u64,
        /// Cost for executing op
        #[serde(rename = "gasCost")]
        pub gas_cost: u64,
        /// Current call depth
        pub depth: u64,
        /// Error message if any
        #[serde(default, skip)]
        pub error: Option<String>,
        /// EVM stack
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub stack: Option<Vec<U256>>,
        /// Last call's return data. Enabled via enableReturnData
        #[serde(
            default,
            rename = "returnData",
            skip_serializing_if = "Option::is_none"
        )]
        pub return_data: Option<Bytes>,
        /// ref <https://github.com/ethereum/go-ethereum/blob/366d2169fbc0e0f803b68c042b77b6b480836dbc/eth/tracers/logger/logger.go#L450-L452>
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub memory: Option<Vec<String>>,
        /// Size of memory.
        #[serde(default, rename = "memSize", skip_serializing_if = "Option::is_none")]
        pub memory_size: Option<u64>,
        /// Storage slots of current contract read from and written to. Only
        /// emitted for SLOAD and SSTORE. Disabled via disableStorage
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            serialize_with = "serialize_string_storage_map_opt"
        )]
        pub storage: Option<BTreeMap<B256, B256>>,
        /// Refund counter
        #[serde(default, rename = "refund", skip_serializing_if = "Option::is_none")]
        pub refund_counter: Option<u64>,
    }

    /// Serializes a storage map as a list of key-value pairs _without_
    /// 0x-prefix
    pub(crate) fn serialize_string_storage_map_opt<S: Serializer>(
        storage: &Option<BTreeMap<B256, B256>>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match storage {
            None => s.serialize_none(),
            Some(storage) => {
                let mut m = s.serialize_map(Some(storage.len()))?;
                for (key, val) in storage.iter() {
                    let key = format!("{:?}", key);
                    let val = format!("{:?}", val);
                    // skip the 0x prefix
                    m.serialize_entry(&key.as_str()[2..], &val.as_str()[2..])?;
                }
                m.end()
            }
        }
    }

    impl TryInto<DefaultFrame> for DefaultFramePrime {
        fn try_into(self) -> Result<DefaultFrame, Self::Error> {
            let a = serde_json::to_string(&self)?;
            let b: DefaultFramePrime = serde_json::from_str(&a)?;
            let c = serde_json::to_string(&b)?;
            let d: DefaultFrame = serde_json::from_str(&c)?;
            Ok(d)
        }

        type Error = anyhow::Error;
    }

    pub fn try_reserialize(structlog_object: &Value) -> anyhow::Result<DefaultFrame> {
        let a = serde_json::to_string(structlog_object)?;
        let b: DefaultFramePrime = serde_json::from_str(&a)?;
        let d: DefaultFrame = b.try_into()?;
        Ok(d)
    }

    pub(crate) async fn normalize_structlog(
        unnormalized_structlog: GethTrace,
    ) -> Option<Vec<StructLog>> {
        match unnormalized_structlog {
            GethTrace::Default(structlog_frame) => Some(structlog_frame.struct_logs),
            GethTrace::JS(structlog_js_object) => try_reserialize(&structlog_js_object)
                .ok()
                .map(|s| s.struct_logs),
            _ => None,
        }
    }
}
