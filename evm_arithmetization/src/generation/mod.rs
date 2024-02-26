use std::collections::{BTreeSet, HashMap};

use anyhow::{anyhow, Error};
use ethereum_types::{Address, BigEndianHash, H256, U256};
use mpt_trie::partial_trie::{HashedPartialTrie, PartialTrie};
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
use crate::cpu::kernel::interpreter::Interpreter;
use crate::generation::state::GenerationState;
use crate::generation::trie_extractor::{get_receipt_trie, get_state_trie, get_txn_trie};
use crate::memory::segments::Segment;
use crate::proof::{
    BlockHashes, BlockMetadata, ExtraBlockData, MemCap, PublicValues, RegistersData, TrieRoots,
};
use crate::prover::{check_abort_signal, get_mem_after_value_from_row};
use crate::util::{h2u, u256_to_u8, u256_to_usize};
use crate::witness::errors::{ProgramError, ProverInputError};
use crate::witness::memory::{MemoryAddress, MemoryChannel, MemoryOp, MemoryOpKind, MemoryState};
use crate::witness::state::RegistersState;
use crate::witness::traces::Traces;
use crate::witness::transition::{final_exception, transition};

pub mod mpt;
pub(crate) mod prover_input;
pub(crate) mod rlp;
pub(crate) mod state;
mod trie_extractor;

use self::mpt::{load_all_mpts, TrieRootPtrs};
use self::state::GenerationStateCheckpoint;
use crate::witness::util::{mem_write_log, mem_write_log_timestamp_zero, stack_peek};

pub const NUM_EXTRA_CYCLES_AFTER: usize = 78;
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

    println!("initial registers {:?}", state.registers);
    let cpu_res = timed!(
        timing,
        "simulate CPU",
        simulate_cpu(&mut state, max_cpu_len)
    );
    let (final_registers, mem_after) = if let Ok(res) = cpu_res {
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
        (RegistersState::default(), None)
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

/// A State is either an `Interpreter` (used for tests and jumpdest analysis) or
/// a `GenerationState`.
pub(crate) enum State<'a, F: Field> {
    Generation(&'a mut GenerationState<F>),
    Interpreter(&'a mut Interpreter<F>),
}

impl<'a, F: Field> State<'a, F> {
    /// Returns a `State`'s `Checkpoint`.
    pub(crate) fn checkpoint(&mut self) -> GenerationStateCheckpoint {
        match self {
            Self::Generation(state) => state.checkpoint(),
            Self::Interpreter(interpreter) => interpreter.checkpoint(),
        }
    }

    /// Increments the `gas_used` register by a value `n`.
    pub(crate) fn incr_gas(&mut self, n: u64) {
        match self {
            Self::Generation(state) => state.registers.gas_used += n,
            Self::Interpreter(interpreter) => interpreter.generation_state.registers.gas_used += n,
        }
    }

    /// Increments the `program_counter` register by a value `n`.
    pub(crate) fn incr_pc(&mut self, n: usize) {
        match self {
            Self::Generation(state) => state.registers.program_counter += n,
            Self::Interpreter(interpreter) => {
                interpreter.generation_state.registers.program_counter += n
            }
        }
    }

    /// Returns a `State`'s registers.
    pub(crate) fn get_registers(&self) -> RegistersState {
        match self {
            Self::Generation(state) => state.registers,
            Self::Interpreter(interpreter) => interpreter.generation_state.registers,
        }
    }

    /// Returns a `State`'s mutable registers.
    pub(crate) fn get_mut_registers(&mut self) -> &mut RegistersState {
        match self {
            Self::Generation(state) => &mut state.registers,
            Self::Interpreter(interpreter) => &mut interpreter.generation_state.registers,
        }
    }

    /// Returns the value stored at address `address` in a `State`.
    pub(crate) fn get_from_memory(&mut self, address: MemoryAddress) -> U256 {
        match self {
            Self::Generation(state) => {
                state
                    .memory
                    .get_with_init(address, false, &HashMap::default())
            }
            Self::Interpreter(interpreter) => interpreter.generation_state.memory.get_with_init(
                address,
                true,
                &interpreter.preinitialized_segments,
            ),
        }
    }

    /// Returns a mutable `GenerationState` from a `State`.
    pub(crate) fn get_mut_generation_state(&mut self) -> &mut GenerationState<F> {
        match self {
            Self::Generation(state) => state,
            Self::Interpreter(interpreter) => &mut interpreter.generation_state,
        }
    }

    /// Returns true if a `State` is a `GenerationState` and false otherwise.
    pub(crate) fn is_generation_state(&mut self) -> bool {
        match self {
            Self::Generation(state) => true,
            Self::Interpreter(interpreter) => false,
        }
    }

    /// Increments the clock of an `Interpreter`'s clock.
    pub(crate) fn incr_interpreter_clock(&mut self) {
        match self {
            Self::Generation(state) => {}
            Self::Interpreter(interpreter) => interpreter.clock += 1,
        }
    }

    /// Returns the value of a `State`'s clock.
    pub(crate) fn get_clock(&mut self) -> usize {
        match self {
            Self::Generation(state) => state.traces.clock(),
            Self::Interpreter(interpreter) => interpreter.clock,
        }
    }

    /// Rolls back a `State`.
    pub(crate) fn rollback(&mut self, checkpoint: GenerationStateCheckpoint) {
        match self {
            Self::Generation(state) => state.rollback(checkpoint),
            Self::Interpreter(interpreter) => interpreter.generation_state.rollback(checkpoint),
        }
    }

    /// Returns a `State`'s stack.
    pub(crate) fn get_stack(&mut self) -> Vec<U256> {
        match self {
            Self::Generation(state) => state.stack(),
            Self::Interpreter(interpreter) => interpreter.stack(),
        }
    }

    fn get_context(&mut self) -> usize {
        match self {
            Self::Generation(state) => state.registers.context,
            Self::Interpreter(interpreter) => interpreter.context(),
        }
    }

    fn get_halt_context(&mut self) -> Option<usize> {
        match self {
            Self::Generation(state) => None,
            Self::Interpreter(interpreter) => interpreter.halt_context,
        }
    }

    /// Returns the content of a the `KernelGeneral` segment of a `State`.
    pub(crate) fn mem_get_kernel_content(&self) -> Vec<Option<U256>> {
        match self {
            Self::Generation(state) => state.memory.contexts[0].segments
                [Segment::KernelGeneral.unscale()]
            .content
            .clone(),
            Self::Interpreter(interpreter) => interpreter.generation_state.memory.contexts[0]
                .segments[Segment::KernelGeneral.unscale()]
            .content
            .clone(),
        }
    }

    /// Applies a `State`'s operations since a checkpoint.
    pub(crate) fn apply_ops(&mut self, checkpoint: GenerationStateCheckpoint) {
        match self {
            Self::Generation(state) => state
                .memory
                .apply_ops(state.traces.mem_ops_since(checkpoint.traces)),
            Self::Interpreter(interpreter) => {
                // An interpreter `checkpoint()` clears all operations before the checkpoint.
                interpreter.apply_memops();
            }
        }
    }
}

fn update_interpreter_final_registers<F: Field>(
    any_state: &mut State<F>,
    final_registers: RegistersState,
) {
    match any_state {
        State::Generation(state) => {}
        State::Interpreter(interpreter) => {
            let registers_after = [
                final_registers.program_counter.into(),
                (final_registers.is_kernel as usize).into(),
                final_registers.stack_len.into(),
                final_registers.stack_top,
                final_registers.context.into(),
                final_registers.gas_used.into(),
            ];

            let length = registers_after.len();
            let registers_after_fields = (0..length)
                .map(|i| {
                    (
                        MemoryAddress::new(0, Segment::RegistersStates, length + i),
                        registers_after[i],
                    )
                })
                .collect::<Vec<_>>();
            interpreter.set_memory_multi_addresses(&registers_after_fields);
        }
    }
}

/// Simulates a CPU. It only generates the traces if the `State` is a
/// `GenerationState`. Otherwise, it simply simulates all operations.
pub(crate) fn run_cpu<F: Field>(
    any_state: &mut State<F>,
    max_cpu_len: Option<usize>,
) -> anyhow::Result<(RegistersState, Option<MemoryState>)> {
    let (is_generation, halt_offsets) = match any_state {
        State::Generation(_state) => (true, vec![KERNEL.global_labels["halt_final"]]),
        State::Interpreter(interpreter) => (false, interpreter.halt_offsets.clone()),
    };

    let halt_pc = KERNEL.global_labels["halt"];
    let halt_final_pc = KERNEL.global_labels["halt_final"];
    let mut final_registers = RegistersState::default();
    let mut final_mem = any_state.get_mut_generation_state().memory.clone();
    let mut running = true;

    loop {
        // If we've reached the kernel's halt routine, and our trace length is a power
        // of 2, stop.
        let registers = any_state.get_registers();
        let pc = registers.program_counter;

        let halt_final = registers.is_kernel && halt_offsets.contains(&pc);
        if running
            && (registers.is_kernel && pc == KERNEL.global_labels["halt"]
                || (max_cpu_len.is_some()
                    && any_state.get_clock() == max_cpu_len.unwrap() - NUM_EXTRA_CYCLES_AFTER))
        {
            running = false;
            final_registers = registers;

            // If `stack_len` is 0, `stack_top` still contains a residual value.
            if final_registers.stack_len == 0 {
                final_registers.stack_top = 0.into();
            }
            // If we are in the interpreter, we need to set the final register values.
            update_interpreter_final_registers(any_state, final_registers);
            final_exception(any_state, is_generation)?;
        }

        let opt_halt_context = any_state.get_halt_context();
        if registers.is_kernel && halt_final {
            if let Some(halt_context) = opt_halt_context {
                if any_state.get_context() == halt_context {
                    // Only happens during jumpdest analysis, we don't care about the output.
                    return Ok((final_registers, Some(final_mem)));
                }
            } else {
                let final_mem = match any_state {
                    State::Generation(state) => None,
                    State::Interpreter(interpreter) => {
                        Some(interpreter.generation_state.memory.clone())
                    }
                };
                log::info!("CPU halted after {} cycles", any_state.get_clock());
                return Ok((final_registers, final_mem));
            }
        }

        transition(any_state)?;
        any_state.incr_interpreter_clock();
    }
}

fn simulate_cpu<F: Field>(
    state: &mut GenerationState<F>,
    max_cpu_len: usize,
) -> anyhow::Result<(RegistersState, Option<MemoryState>)> {
    let (final_registers, mem_after) = run_cpu(&mut State::Generation(state), Some(max_cpu_len))?;

    let pc = state.registers.program_counter;
    // Padding
    let mut row = CpuColumnsView::<F>::default();
    row.clock = F::from_canonical_usize(state.traces.clock());
    row.context = F::from_canonical_usize(state.registers.context);
    row.program_counter = F::from_canonical_usize(pc);
    row.is_kernel_mode = F::ONE;
    row.gas = F::from_canonical_u64(state.registers.gas_used);
    row.stack_len = F::from_canonical_usize(state.registers.stack_len);

    loop {
        // If our trace length is a power of 2, stop.
        state.traces.push_cpu(true, row);
        row.clock += F::ONE;
        if (state.traces.clock() - 1).is_power_of_two() {
            break;
        }
    }

    log::info!("CPU trace padded to {} cycles", state.traces.clock() - 1);

    Ok((final_registers, mem_after))
}
