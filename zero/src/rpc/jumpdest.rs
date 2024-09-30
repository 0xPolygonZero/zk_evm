use core::default::Default;
use core::option::Option::None;
use core::str::FromStr as _;
use core::time::Duration;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::ops::Not as _;

use __compat_primitive_types::H160;
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
use evm_arithmetization::CodeDb;
use keccak_hash::keccak;
use structlogprime::normalize_structlog;
use tokio::time::timeout;
use trace_decoder::is_precompile;
use trace_decoder::ContractCodeUsage;
use trace_decoder::TxnTrace;
use tracing::trace;

/// The maximum time we are willing to wait for a structlog before failing over
/// to simulating the JumpDest analysis.
const TIMEOUT_LIMIT: Duration = Duration::from_secs(10 * 60);

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

/// Get code hash from a read or write operation of contract code.
fn get_code_hash(usage: &ContractCodeUsage) -> H256 {
    match usage {
        ContractCodeUsage::Read(hash) => *hash,
        ContractCodeUsage::Write(bytes) => keccak(bytes),
    }
}

/// Predicate that determines whether a `StructLog` that includes memory is
/// required.
fn trace_contains_create(structlog: &[StructLog]) -> bool {
    structlog
        .iter()
        .any(|entry| entry.op == "CREATE" || entry.op == "CREATE2")
}

/// Gets the lightest possible structlog for transcation `tx_hash`.
pub(crate) async fn get_normalized_structlog<ProviderT, TransportT>(
    provider: &ProviderT,
    tx_hash: &B256,
) -> Result<Option<Vec<StructLog>>, RpcError<TransportErrorKind>>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    let inner = async {
        // Optimization: It may be a better default to pull the stack immediately.
        let stackonly_structlog_trace = provider
            .debug_trace_transaction(*tx_hash, structlog_tracing_options(true, false, false))
            .await?;

        let stackonly_structlog_opt: Option<Vec<StructLog>> =
            normalize_structlog(&stackonly_structlog_trace).await;

        let need_memory = stackonly_structlog_opt
            .as_deref()
            .is_some_and(trace_contains_create);
        trace!("Need structlog with memory: {need_memory}");

        if need_memory.not() {
            return Ok(stackonly_structlog_opt);
        };

        let memory_structlog_fut = provider.debug_trace_transaction(
            *tx_hash,
            structlog_tracing_options(true, need_memory, false),
        );

        let memory_structlog = normalize_structlog(&memory_structlog_fut.await?).await;

        Ok::<Option<Vec<_>>, RpcError<TransportErrorKind>>(memory_structlog)
    };

    match timeout(TIMEOUT_LIMIT, inner).await {
        Err(ellapsed_error) => Err(RpcError::Transport(TransportErrorKind::Custom(Box::new(
            ellapsed_error,
        )))),
        Ok(structlog_res) => Ok(structlog_res?),
    }
}

/// Generate at JUMPDEST table by simulating the call stack in EVM,
/// using a Geth structlog as input.
pub(crate) fn generate_jumpdest_table(
    tx: &Transaction,
    struct_log: &[StructLog],
    tx_traces: &BTreeMap<Address, TxnTrace>,
) -> anyhow::Result<(JumpDestTableWitness, CodeDb)> {
    trace!("Generating JUMPDEST table for tx: {}", tx.hash);

    let mut jumpdest_table = JumpDestTableWitness::default();
    let mut code_db = CodeDb::default();

    // This map does not contain `initcodes`.
    let callee_addr_to_code_hash: HashMap<Address, H256> = tx_traces
        .iter()
        .map(|(callee_addr, trace)| (callee_addr, &trace.code_usage))
        .filter(|(_callee_addr, code_usage)| code_usage.is_some())
        .map(|(callee_addr, code_usage)| {
            (*callee_addr, get_code_hash(code_usage.as_ref().unwrap()))
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
        Some(to_address) if is_precompile(H160::from_str(&to_address.to_string())?) => {
            return Ok((jumpdest_table, code_db))
        }
        Some(to_address) if callee_addr_to_code_hash.contains_key(&to_address).not() => {
            return Ok((jumpdest_table, code_db))
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

        ensure!(
            call_stack.is_empty().not(),
            "Call stack was unexpectedly empty."
        );
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
                prev_jump = None;
                ensure!(entry.stack.as_ref().is_some(), "No evm stack found.");
                // We reverse the stack, so the order matches our assembly code.
                let evm_stack: Vec<_> = entry.stack.as_ref().unwrap().iter().rev().collect();
                // These opcodes expect 6 or 7 operands on the stack, but for jumpdest-table
                // generation we only use 2, and failures will be handled in
                // next iteration by popping the stack accordingly.
                let operands_used = 2;

                if evm_stack.len() < operands_used {
                    trace!( "Opcode {op} expected {operands_used} operands at the EVM stack, but only {} were found.", evm_stack.len());
                    // Note for future debugging:  There may exist edge cases, where the call
                    // context has been incremented before the call op fails. This should be
                    // accounted for before this and the following `continue`.  The details are
                    // defined in `sys_calls.asm`.
                    continue;
                }
                // This is the same stack index (i.e. 2nd) for all four opcodes. See https://ethervm.io/#F1
                let [_gas, address, ..] = evm_stack[..] else {
                    unreachable!()
                };

                if *address > U256::from(U160::MAX) {
                    trace!(
                        "{op}: Callee address {} was larger than possible {}.",
                        *address,
                        U256::from(U160::MAX)
                    );
                    // Se note above.
                    continue;
                };
                let lower_20_bytes = U160::from(*address);
                let callee_address = Address::from(lower_20_bytes);

                if callee_addr_to_code_hash.contains_key(&callee_address) {
                    let next_code_hash = callee_addr_to_code_hash[&callee_address];
                    call_stack.push((next_code_hash, next_ctx_available));
                };

                if is_precompile(H160::from_str(&callee_address.to_string())?) {
                    trace!("Called precompile at address {}.", &callee_address);
                };

                if callee_addr_to_code_hash.contains_key(&callee_address).not()
                    && is_precompile(H160::from_str(&callee_address.to_string())?).not()
                {
                    // This case happens if calling an EOA. This is described
                    // under opcode `STOP`: https://www.evm.codes/#00?fork=cancun
                    trace!(
                        "Callee address {} has no associated `code_hash`.",
                        &callee_address
                    );
                }
                next_ctx_available += 1;
            }
            "CREATE" | "CREATE2" => {
                prev_jump = None;
                ensure!(entry.stack.as_ref().is_some(), "No evm stack found.");
                // We reverse the stack, so the order matches our assembly code.
                let evm_stack: Vec<_> = entry.stack.as_ref().unwrap().iter().rev().collect();
                let operands_used = 3;

                if evm_stack.len() < operands_used {
                    trace!( "Opcode {op} expected {operands_used} operands at the EVM stack, but only {} were found.", evm_stack.len() );
                    continue;
                };

                let [_value, offset, size, ..] = evm_stack[..] else {
                    unreachable!()
                };
                if *offset > U256::from(usize::MAX) {
                    trace!(
                        "{op}: Offset {offset} was too large to fit in usize {}.",
                        usize::MAX
                    );
                    continue;
                };
                let offset: usize = offset.to();

                if *size > U256::from(usize::MAX) {
                    trace!(
                        "{op}: Size {size} was too large to fit in usize {}.",
                        usize::MAX
                    );
                    continue;
                };
                let size: usize = size.to();

                let memory_size = entry.memory.as_ref().unwrap().len() * WORDSIZE;

                if entry.memory.is_none() || offset + size > memory_size {
                    trace!("Insufficient memory available for {op}. Contract has size {size} and is supposed to be stored between offset {offset} and {}, but memory size is only {memory_size}.", offset+size);
                    continue;
                }
                let memory_raw: &[String] = entry.memory.as_ref().unwrap();
                let memory_parsed: Vec<anyhow::Result<Word>> = memory_raw
                    .iter()
                    .map(|mem_line| {
                        let mem_line_parsed = U256::from_str_radix(mem_line, 16)?;
                        Ok(mem_line_parsed.to_be_bytes())
                    })
                    .collect();
                let mem_res: anyhow::Result<Vec<Word>> = memory_parsed.into_iter().collect();
                if mem_res.is_err() {
                    trace!(
                        "{op}: Parsing memory failed with error: {}",
                        mem_res.unwrap_err()
                    );
                    continue;
                }
                let memory: Vec<u8> = mem_res.unwrap().concat();

                let init_code = &memory[offset..offset + size];
                code_db.insert(init_code.to_vec());
                let init_code_hash = keccak(init_code);
                call_stack.push((init_code_hash, next_ctx_available));

                next_ctx_available += 1;
            }
            "JUMP" => {
                prev_jump = None;
                ensure!(entry.stack.as_ref().is_some(), "No evm stack found.");
                // We reverse the stack, so the order matches our assembly code.
                let evm_stack: Vec<_> = entry.stack.as_ref().unwrap().iter().rev().collect();
                let operands = 1;
                if evm_stack.len() < operands {
                    trace!( "Opcode {op} expected {operands} operands at the EVM stack, but only {} were found.", evm_stack.len() );
                    continue;
                }
                let [jump_target, ..] = evm_stack[..] else {
                    unreachable!()
                };

                prev_jump = Some(*jump_target);
            }
            "JUMPI" => {
                prev_jump = None;
                ensure!(entry.stack.as_ref().is_some(), "No evm stack found.");
                // We reverse the stack, so the order matches our assembly code.
                let evm_stack: Vec<_> = entry.stack.as_ref().unwrap().iter().rev().collect();
                let operands = 2;
                if evm_stack.len() < operands {
                    trace!( "Opcode {op} expected {operands} operands at the EVM stack, but only {} were found.", evm_stack.len());
                    continue;
                };

                let [jump_target, condition, ..] = evm_stack[..] else {
                    unreachable!()
                };
                let jump_condition = condition.is_zero().not();

                if jump_condition {
                    prev_jump = Some(*jump_target)
                }
            }
            "JUMPDEST" => {
                let mut jumped_here = false;

                if let Some(jmp_target) = prev_jump {
                    jumped_here = jmp_target == U256::from(entry.pc);
                }
                prev_jump = None;

                if jumped_here.not() {
                    trace!(
                        "{op}: JUMPDESTs at offset {} was reached through fall-through.",
                        entry.pc
                    );
                    continue;
                }

                let jumpdest_offset = TryInto::<usize>::try_into(entry.pc);
                if jumpdest_offset.is_err() {
                    trace!(
                        "{op}: Could not cast offset {} to usize {}.",
                        entry.pc,
                        usize::MAX
                    );
                    continue;
                }
                assert!(jumpdest_offset.unwrap() < 24576);
                jumpdest_table.insert(*code_hash, *ctx, jumpdest_offset.unwrap());
            }
            "EXTCODECOPY" | "EXTCODESIZE" => {
                prev_jump = None;
                next_ctx_available += 1;
            }
            _ => {
                prev_jump = None;
            }
        }
    }
    Ok((jumpdest_table, code_db))
}

/// This module exists as a workaround for parsing `StructLog`.  The `error`
/// field is a string in Alloy but an object in Erigon.
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
        unnormalized_structlog: &GethTrace,
    ) -> Option<Vec<StructLog>> {
        match unnormalized_structlog {
            GethTrace::Default(structlog_frame) => Some(structlog_frame.struct_logs.clone()),
            GethTrace::JS(structlog_js_object) => try_reserialize(structlog_js_object)
                .ok()
                .map(|s| s.struct_logs),
            _ => None,
        }
    }
}
