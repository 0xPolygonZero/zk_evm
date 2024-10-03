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
use alloy::rpc::types::trace::geth::GethTrace;
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
            trace2structlog(stackonly_structlog_trace).unwrap_or_default();

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

        let memory_structlog = trace2structlog(memory_structlog_fut.await?).unwrap_or_default();

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

    // This map does neither contain the `init` field of Contract Deployment
    // transactions nor CREATE, CREATE2 payloads.
    let callee_addr_to_code_hash: HashMap<Address, H256> = tx_traces
        .iter()
        .filter_map(|(callee_addr, trace)| {
            trace
                .code_usage
                .as_ref()
                .map(|code| (*callee_addr, get_code_hash(code)))
        })
        .collect();

    // REVIEW: will be removed before merge
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

        // REVIEW: will be removed before merge
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

fn trace2structlog(trace: GethTrace) -> Result<Option<Vec<StructLog>>, serde_json::Error> {
    match trace {
        GethTrace::Default(it) => Ok(Some(it.struct_logs)),
        GethTrace::JS(it) => Ok(Some(compat::deserialize(it)?.struct_logs)),
        _ => Ok(None),
    }
}
/// This module exists as a workaround for parsing `StructLog`.  The `error`
/// field is a string in Geth and Alloy but an object in Erigon. A PR[^1] has
/// been merged to fix this upstream and should eventually render this
/// unnecessary. [^1]: `https://github.com/erigontech/erigon/pull/12089`
mod compat {
    use std::{collections::BTreeMap, fmt, iter};

    use alloy::rpc::types::trace::geth::{DefaultFrame, StructLog};
    use alloy_primitives::{Bytes, B256, U256};
    use serde::{de::SeqAccess, Deserialize, Deserializer};

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DefaultFrame, D::Error> {
        _DefaultFrame::deserialize(d)
    }

    /// The `error` field is a `string` in `geth` etc. but an `object` in
    /// `erigon`.
    fn error<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Error {
            String(String),
            #[allow(dead_code)]
            Object(serde_json::Map<String, serde_json::Value>),
        }
        Ok(match Error::deserialize(d)? {
            Error::String(it) => Some(it),
            Error::Object(_) => None,
        })
    }

    #[derive(Deserialize)]
    #[serde(remote = "DefaultFrame", rename_all = "camelCase")]
    struct _DefaultFrame {
        failed: bool,
        gas: u64,
        return_value: Bytes,
        #[serde(deserialize_with = "vec_structlog")]
        struct_logs: Vec<StructLog>,
    }

    fn vec_structlog<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<StructLog>, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Vec<StructLog>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an array of `StructLog`")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                #[derive(Deserialize)]
                struct With(#[serde(with = "_StructLog")] StructLog);
                let v = iter::from_fn(|| seq.next_element().transpose())
                    .map(|it| it.map(|With(it)| it))
                    .collect::<Result<_, _>>()?;
                Ok(v)
            }
        }

        d.deserialize_seq(Visitor)
    }

    #[derive(Deserialize)]
    #[serde(remote = "StructLog", rename_all = "camelCase")]
    struct _StructLog {
        pc: u64,
        op: String,
        gas: u64,
        gas_cost: u64,
        depth: u64,
        #[serde(deserialize_with = "error")]
        error: Option<String>,
        stack: Option<Vec<U256>>,
        return_data: Option<Bytes>,
        memory: Option<Vec<String>>,
        #[serde(rename = "memSize")]
        memory_size: Option<u64>,
        storage: Option<BTreeMap<B256, B256>>,
        #[serde(rename = "refund")]
        refund_counter: Option<u64>,
    }
}
