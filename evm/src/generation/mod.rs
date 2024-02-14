use std::collections::{BTreeSet, HashMap};

use anyhow::anyhow;
use eth_trie_utils::partial_trie::{HashedPartialTrie, PartialTrie};
use ethereum_types::{Address, BigEndianHash, H256, U256};
use plonky2::field::extension::Extendable;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use serde::{Deserialize, Serialize};
use starky::config::StarkConfig;
use GlobalMetadata::{
    ReceiptTrieRootDigestAfter, ReceiptTrieRootDigestBefore, StateTrieRootDigestAfter,
    StateTrieRootDigestBefore, TransactionTrieRootDigestAfter, TransactionTrieRootDigestBefore,
};

use crate::all_stark::{AllStark, NUM_TABLES};
use crate::cpu::columns::CpuColumnsView;
use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::assembler::Kernel;
use crate::cpu::kernel::constants::context_metadata::ContextMetadata;
use crate::cpu::kernel::constants::global_metadata::GlobalMetadata;
use crate::generation::state::GenerationState;
use crate::generation::trie_extractor::{get_receipt_trie, get_state_trie, get_txn_trie};
use crate::memory::segments::Segment;
use crate::proof::{
    BlockHashes, BlockMetadata, ExtraBlockData, MemCap, PublicValues, RegistersData, TrieRoots,
};
use crate::prover::{check_abort_signal, get_mem_after_value_from_row};
use crate::util::{h2u, u256_to_u8, u256_to_usize};
use crate::witness::errors::{ProgramError, ProverInputError};
use crate::witness::memory::{MemoryAddress, MemoryChannel, MemoryOp, MemoryState};
use crate::witness::state::RegistersState;
use crate::witness::traces::Traces;
use crate::witness::transition::{final_exception, transition};

pub mod mpt;
pub(crate) mod prover_input;
pub(crate) mod rlp;
pub(crate) mod state;
mod trie_extractor;

use self::mpt::{load_all_mpts, TrieRootPtrs};
use crate::witness::util::{mem_write_log, mem_write_log_timestamp_zero, stack_peek};

pub const NUM_EXTRA_CYCLES_AFTER: usize = 78;
pub const NUM_EXTRA_CYCLES_BEFORE: usize = 64;
/// Memory values used to initialize `MemBefore`.
pub type MemBeforeValues = Vec<(MemoryAddress, U256)>;

/// Inputs needed for trace generation.
#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct GenerationInputs {
    /// The index of the transaction being proven within its block.
    pub txn_number_before: U256,
    /// The cumulative gas used through the execution of all transactions prior
    /// the current one.
    pub gas_used_before: U256,
    /// The cumulative gas used after the execution of the current transaction.
    /// The exact gas used by the current transaction is `gas_used_after` -
    /// `gas_used_before`.
    pub gas_used_after: U256,

    /// A None would yield an empty proof, otherwise this contains the encoding
    /// of a transaction.
    pub signed_txn: Option<Vec<u8>>,
    /// Withdrawal pairs `(addr, amount)`. At the end of the txs, `amount` is
    /// added to `addr`'s balance. See EIP-4895.
    pub withdrawals: Vec<(Address, U256)>,
    pub tries: TrieInputs,
    /// Expected trie roots after the transactions are executed.
    pub trie_roots_after: TrieRoots,

    /// State trie root of the checkpoint block.
    /// This could always be the genesis block of the chain, but it allows a
    /// prover to continue proving blocks from certain checkpoint heights
    /// without requiring proofs for blocks past this checkpoint.
    pub checkpoint_state_trie_root: H256,

    /// Mapping between smart contract code hashes and the contract byte code.
    /// All account smart contracts that are invoked will have an entry present.
    pub contract_code: HashMap<H256, Vec<u8>>,

    /// Information contained in the block header.
    pub block_metadata: BlockMetadata,

    /// The hash of the current block, and a list of the 256 previous block
    /// hashes.
    pub block_hashes: BlockHashes,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct TrieInputs {
    /// A partial version of the state trie prior to these transactions. It
    /// should include all nodes that will be accessed by these
    /// transactions.
    pub state_trie: HashedPartialTrie,

    /// A partial version of the transaction trie prior to these transactions.
    /// It should include all nodes that will be accessed by these
    /// transactions.
    pub transactions_trie: HashedPartialTrie,

    /// A partial version of the receipt trie prior to these transactions. It
    /// should include all nodes that will be accessed by these
    /// transactions.
    pub receipts_trie: HashedPartialTrie,

    /// A partial version of each storage trie prior to these transactions. It
    /// should include all storage tries, and nodes therein, that will be
    /// accessed by these transactions.
    pub storage_tries: Vec<(H256, HashedPartialTrie)>,
}

pub(crate) struct SegmentData<F: RichField> {
    pub(crate) max_cpu_len: usize,
    pub(crate) starting_state: GenerationState<F>,
    pub(crate) memory_before: Vec<(MemoryAddress, U256)>,
    pub(crate) registers_before: RegistersData,
    pub(crate) registers_after: RegistersData,
}

fn apply_metadata_and_tries_memops<F: RichField + Extendable<D>, const D: usize>(
    state: &mut GenerationState<F>,
    inputs: &GenerationInputs,
    registers_before: &RegistersData,
    registers_after: &RegistersData,
) {
    let metadata = &inputs.block_metadata;
    let tries = &inputs.tries;
    let trie_roots_after = &inputs.trie_roots_after;
    let fields = [
        (
            GlobalMetadata::BlockBeneficiary,
            U256::from_big_endian(&metadata.block_beneficiary.0),
        ),
        (GlobalMetadata::BlockTimestamp, metadata.block_timestamp),
        (GlobalMetadata::BlockNumber, metadata.block_number),
        (GlobalMetadata::BlockDifficulty, metadata.block_difficulty),
        (
            GlobalMetadata::BlockRandom,
            metadata.block_random.into_uint(),
        ),
        (GlobalMetadata::BlockGasLimit, metadata.block_gaslimit),
        (GlobalMetadata::BlockChainId, metadata.block_chain_id),
        (GlobalMetadata::BlockBaseFee, metadata.block_base_fee),
        (
            GlobalMetadata::BlockCurrentHash,
            h2u(inputs.block_hashes.cur_hash),
        ),
        (GlobalMetadata::BlockGasUsed, metadata.block_gas_used),
        (GlobalMetadata::BlockGasUsedBefore, inputs.gas_used_before),
        (GlobalMetadata::BlockGasUsedAfter, inputs.gas_used_after),
        (GlobalMetadata::TxnNumberBefore, inputs.txn_number_before),
        (
            GlobalMetadata::TxnNumberAfter,
            inputs.txn_number_before + if inputs.signed_txn.is_some() { 1 } else { 0 },
        ),
        (
            GlobalMetadata::StateTrieRootDigestBefore,
            h2u(tries.state_trie.hash()),
        ),
        (
            GlobalMetadata::TransactionTrieRootDigestBefore,
            h2u(tries.transactions_trie.hash()),
        ),
        (
            GlobalMetadata::ReceiptTrieRootDigestBefore,
            h2u(tries.receipts_trie.hash()),
        ),
        (
            GlobalMetadata::StateTrieRootDigestAfter,
            h2u(trie_roots_after.state_root),
        ),
        (
            GlobalMetadata::TransactionTrieRootDigestAfter,
            h2u(trie_roots_after.transactions_root),
        ),
        (
            GlobalMetadata::ReceiptTrieRootDigestAfter,
            h2u(trie_roots_after.receipts_root),
        ),
        (GlobalMetadata::KernelHash, h2u(KERNEL.code_hash)),
        (GlobalMetadata::KernelLen, KERNEL.code.len().into()),
    ];

    let channel = MemoryChannel::GeneralPurpose(0);
    let mut ops = fields
        .map(|(field, val)| {
            mem_write_log(
                channel,
                // These fields are already scaled by their segment, and are in context 0 (kernel).
                MemoryAddress::new_bundle(U256::from(field as usize)).unwrap(),
                state,
                val,
            )
        })
        .to_vec();

    // Write the block's final block bloom filter.
    ops.extend((0..8).map(|i| {
        mem_write_log(
            channel,
            MemoryAddress::new(0, Segment::GlobalBlockBloom, i),
            state,
            metadata.block_bloom[i],
        )
    }));

    // Write previous block hashes.
    ops.extend(
        (0..256)
            .map(|i| {
                mem_write_log(
                    channel,
                    MemoryAddress::new(0, Segment::BlockHashes, i),
                    state,
                    h2u(inputs.block_hashes.prev_hashes[i]),
                )
            })
            .collect::<Vec<_>>(),
    );

    // Write initial registers.
    let registers_before = [
        registers_before.program_counter,
        registers_before.is_kernel,
        registers_before.stack_len,
        registers_before.stack_top,
        registers_before.context,
        registers_before.gas_used,
    ];
    ops.extend((0..registers_before.len()).map(|i| {
        mem_write_log(
            channel,
            MemoryAddress::new(0, Segment::RegistersStates, i),
            state,
            registers_before[i],
        )
    }));

    let length = registers_before.len();

    // Write final registers.
    let registers_after = [
        registers_after.program_counter,
        registers_after.is_kernel,
        registers_after.stack_len,
        registers_after.stack_top,
        registers_after.context,
        registers_after.gas_used,
    ];
    ops.extend((0..registers_before.len()).map(|i| {
        mem_write_log(
            channel,
            MemoryAddress::new(0, Segment::RegistersStates, length + i),
            state,
            registers_after[i],
        )
    }));

    state.memory.apply_ops(&ops);
    state.traces.memory_ops.extend(ops);
}

pub(crate) fn generate_traces<F: RichField + Extendable<D>, const D: usize>(
    all_stark: &AllStark<F, D>,
    inputs: GenerationInputs,
    config: &StarkConfig,
    segment_data: SegmentData<F>,
    timing: &mut TimingTree,
) -> anyhow::Result<(
    [Vec<PolynomialValues<F>>; NUM_TABLES],
    PublicValues,
    Vec<Vec<F>>,
)> {
    // Initialize the state with the state at the end of the
    // previous segment execution, if any.

    let SegmentData {
        max_cpu_len,
        starting_state: mut state,
        memory_before,
        registers_before,
        registers_after,
    } = segment_data;

    for &(address, val) in &memory_before {
        state.memory.set(address, val);
    }

    apply_metadata_and_tries_memops(&mut state, &inputs, &registers_before, &registers_after);

    let cpu_res = timed!(
        timing,
        "simulate CPU",
        simulate_cpu(&mut state, max_cpu_len)
    );
    let final_registers = if let Ok(res) = cpu_res {
        res
    } else {
        // Retrieve previous PC (before jumping to KernelPanic), to see if we reached
        // `hash_final_tries`. We will output debugging information on the final
        // tries only if we got a root mismatch.
        let previous_pc = state
            .traces
            .cpu
            .last()
            .expect("We should have CPU rows")
            .program_counter
            .to_canonical_u64() as usize;

        if KERNEL.offset_name(previous_pc).contains("hash_final_tries") {
            let state_trie_ptr = u256_to_usize(
                state
                    .memory
                    .read_global_metadata(GlobalMetadata::StateTrieRoot),
            )
            .map_err(|_| anyhow!("State trie pointer is too large to fit in a usize."))?;
            log::debug!(
                "Computed state trie: {:?}",
                get_state_trie::<HashedPartialTrie>(&state.memory, state_trie_ptr)
            );

            let txn_trie_ptr = u256_to_usize(
                state
                    .memory
                    .read_global_metadata(GlobalMetadata::TransactionTrieRoot),
            )
            .map_err(|_| anyhow!("Transactions trie pointer is too large to fit in a usize."))?;
            log::debug!(
                "Computed transactions trie: {:?}",
                get_txn_trie::<HashedPartialTrie>(&state.memory, txn_trie_ptr)
            );

            let receipt_trie_ptr = u256_to_usize(
                state
                    .memory
                    .read_global_metadata(GlobalMetadata::ReceiptTrieRoot),
            )
            .map_err(|_| anyhow!("Receipts trie pointer is too large to fit in a usize."))?;
            log::debug!(
                "Computed receipts trie: {:?}",
                get_receipt_trie::<HashedPartialTrie>(&state.memory, receipt_trie_ptr)
            );
        }

        cpu_res?;
        RegistersState::default()
    };

    log::info!(
        "Trace lengths (before padding): {:?}",
        state.traces.get_lengths()
    );

    let read_metadata = |field| state.memory.read_global_metadata(field);
    let trie_roots_before = TrieRoots {
        state_root: H256::from_uint(&read_metadata(StateTrieRootDigestBefore)),
        transactions_root: H256::from_uint(&read_metadata(TransactionTrieRootDigestBefore)),
        receipts_root: H256::from_uint(&read_metadata(ReceiptTrieRootDigestBefore)),
    };
    let trie_roots_after = TrieRoots {
        state_root: H256::from_uint(&read_metadata(StateTrieRootDigestAfter)),
        transactions_root: H256::from_uint(&read_metadata(TransactionTrieRootDigestAfter)),
        receipts_root: H256::from_uint(&read_metadata(ReceiptTrieRootDigestAfter)),
    };

    let gas_used_after = read_metadata(GlobalMetadata::BlockGasUsedAfter);
    let txn_number_after = read_metadata(GlobalMetadata::TxnNumberAfter);

    let extra_block_data = ExtraBlockData {
        checkpoint_state_trie_root: inputs.checkpoint_state_trie_root,
        txn_number_before: inputs.txn_number_before,
        txn_number_after,
        gas_used_before: inputs.gas_used_before,
        gas_used_after,
    };

    // `mem_before` and `mem_after` are intialized with an empty cap.
    // But they are set to the caps of `MemBefore` and `MemAfter`
    // respectively while proving.
    let public_values = PublicValues {
        trie_roots_before,
        trie_roots_after,
        block_metadata: inputs.block_metadata,
        block_hashes: inputs.block_hashes,
        extra_block_data,
        registers_before,
        registers_after,
        mem_before: MemCap { mem_cap: vec![] },
        mem_after: MemCap { mem_cap: vec![] },
    };

    let (tables, final_values) = timed!(
        timing,
        "convert trace data to tables",
        state
            .traces
            .into_tables(all_stark, &memory_before, config, timing)
    );
    Ok((tables, public_values, final_values))
}

fn simulate_cpu<F: Field>(
    state: &mut GenerationState<F>,
    max_cpu_len: usize,
) -> anyhow::Result<RegistersState> {
    let halt_pc = KERNEL.global_labels["halt"];
    let halt_final_pc = KERNEL.global_labels["halt_final"];
    let mut final_registers = RegistersState::default();
    let mut running = true;
    loop {
        // If we've reached the kernel's halt routine, and our trace length is a power
        // of 2, stop.
        let pc = state.registers.program_counter;
        let halt = state.registers.is_kernel && pc == halt_pc;
        // If the maximum trace length (minus some cycles for running `exc_stop`) is
        // reached, or if we reached the halt routine, raise the stop exception.
        if running && (halt || state.traces.clock() == max_cpu_len - NUM_EXTRA_CYCLES_AFTER) {
            running = false;
            final_registers = state.registers;
            // If `stack_len` is 0, `stack_top` still contains a residual value.
            if final_registers.stack_len == 0 {
                final_registers.stack_top = 0.into();
            }
            final_exception(state)?;
        }
        let halt_final = pc == halt_final_pc;
        if halt_final {
            log::info!("CPU halted after {} cycles", state.traces.clock());
            log::info!(
                "halt label at {}, halt_final label at {}",
                halt_pc,
                halt_final_pc
            );

            // Padding
            let mut row = CpuColumnsView::<F>::default();
            row.clock = F::from_canonical_usize(state.traces.clock());
            row.context = F::from_canonical_usize(state.registers.context);
            row.program_counter = F::from_canonical_usize(pc);
            row.is_kernel_mode = F::ONE;
            row.gas = F::from_canonical_u64(state.registers.gas_used);
            row.stack_len = F::from_canonical_usize(state.registers.stack_len);

            loop {
                state.traces.push_cpu(row);
                row.clock += F::ONE;
                if (state.traces.clock() - 1).is_power_of_two() {
                    break;
                }
            }

            log::info!("CPU trace padded to {} cycles", state.traces.clock() - 1);

            return Ok(final_registers);
        }

        transition(state)?;
    }
    Ok(final_registers)
}

fn simulate_cpu_between_labels_and_get_user_jumps<F: Field>(
    initial_label: &str,
    final_label: &str,
    state: &mut GenerationState<F>,
) -> Option<HashMap<usize, BTreeSet<usize>>> {
    if state.jumpdest_table.is_some() {
        None
    } else {
        const JUMP_OPCODE: u8 = 0x56;
        const JUMPI_OPCODE: u8 = 0x57;

        let halt_pc = KERNEL.global_labels[final_label];
        let mut jumpdest_addresses: HashMap<_, BTreeSet<usize>> = HashMap::new();

        state.registers.program_counter = KERNEL.global_labels[initial_label];
        let initial_clock = state.traces.clock();
        let initial_context = state.registers.context;

        log::debug!("Simulating CPU for jumpdest analysis.");

        loop {
            // skip jumpdest table validations in simulations
            if state.registers.is_kernel
                && state.registers.program_counter == KERNEL.global_labels["jumpdest_analysis"]
            {
                state.registers.program_counter = KERNEL.global_labels["jumpdest_analysis_end"]
            }
            let pc = state.registers.program_counter;
            let context = state.registers.context;
            let mut halt = state.registers.is_kernel
                && pc == halt_pc
                && state.registers.context == initial_context;
            let Ok(opcode) = u256_to_u8(state.memory.get(MemoryAddress::new(
                context,
                Segment::Code,
                state.registers.program_counter,
            ))) else {
                log::debug!(
                    "Simulated CPU for jumpdest analysis halted after {} cycles",
                    state.traces.clock() - initial_clock
                );
                return Some(jumpdest_addresses);
            };
            let cond = if let Ok(cond) = stack_peek(state, 1) {
                cond != U256::zero()
            } else {
                false
            };
            if !state.registers.is_kernel
                && (opcode == JUMP_OPCODE || (opcode == JUMPI_OPCODE && cond))
            {
                // Avoid deeper calls to abort
                let Ok(jumpdest) = u256_to_usize(state.registers.stack_top) else {
                    log::debug!(
                        "Simulated CPU for jumpdest analysis halted after {} cycles",
                        state.traces.clock() - initial_clock
                    );
                    return Some(jumpdest_addresses);
                };
                state.memory.set(
                    MemoryAddress::new(context, Segment::JumpdestBits, jumpdest),
                    U256::one(),
                );
                let jumpdest_opcode =
                    state
                        .memory
                        .get(MemoryAddress::new(context, Segment::Code, jumpdest));
                if let Some(ctx_addresses) = jumpdest_addresses.get_mut(&context) {
                    ctx_addresses.insert(jumpdest);
                } else {
                    jumpdest_addresses.insert(context, BTreeSet::from([jumpdest]));
                }
            }
            if halt {
                final_exception(state);
            }
            let halt_final = state.registers.program_counter == KERNEL.global_labels["halt_final"];
            if halt_final || transition(state).is_err() {
                log::debug!(
                    "Simulated CPU for jumpdest analysis halted after {} cycles",
                    state.traces.clock() - initial_clock
                );
                return Some(jumpdest_addresses);
            }
        }
    }
}
