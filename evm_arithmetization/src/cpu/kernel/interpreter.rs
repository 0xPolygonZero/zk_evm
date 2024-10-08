//! An EVM interpreter, allowing to execute the zkEVM CPU without keeping track
//! of co-processor operations to fill out their execution traces.
//! This is useful for testing and debugging purposes, but also in the context
//! of jumpdest analysis simulation, where it allows the prover to skim through
//! the future execution and generate nondeterministically the corresponding
//! jumpdest table, before the actual CPU carries on with contract execution.

use std::collections::{BTreeSet, HashMap};

use anyhow::anyhow;
use ethereum_types::{BigEndianHash, U256};
use log::Level;
use mpt_trie::partial_trie::PartialTrie;
use plonky2::hash::hash_types::RichField;
use serde::{Deserialize, Serialize};

use crate::byte_packing::byte_packing_stark::BytePackingOp;
use crate::cpu::columns::CpuColumnsView;
use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::constants::context_metadata::ContextMetadata;
use crate::cpu::kernel::constants::global_metadata::GlobalMetadata;
use crate::generation::debug_inputs;
use crate::generation::linked_list::LinkedListsPtrs;
use crate::generation::mpt::{load_linked_lists_and_txn_and_receipt_mpts, TrieRootPtrs};
use crate::generation::rlp::all_rlp_prover_inputs_reversed;
use crate::generation::state::{
    all_ger_prover_inputs, all_withdrawals_prover_inputs_reversed, GenerationState,
    GenerationStateCheckpoint,
};
use crate::generation::{state::State, GenerationInputs};
use crate::keccak_sponge::columns::KECCAK_WIDTH_BYTES;
use crate::keccak_sponge::keccak_sponge_stark::KeccakSpongeOp;
use crate::memory::segments::Segment;
use crate::structlog::TxZeroStructLogs;
use crate::util::h2u;
use crate::witness::errors::ProgramError;
use crate::witness::memory::{
    MemoryAddress, MemoryContextState, MemoryOp, MemoryOpKind, MemorySegmentState, MemoryState,
};
use crate::witness::operation::Operation;
use crate::witness::state::RegistersState;
use crate::witness::transition::{
    decode, fill_op_flag, get_op_special_length, log_kernel_instruction, Transition,
};
use crate::{arithmetic, keccak, logic};

/// Halt interpreter execution whenever a jump to this offset is done.
const DEFAULT_HALT_OFFSET: usize = 0xdeadbeef;

pub(crate) struct Interpreter<F: RichField> {
    /// The interpreter holds a `GenerationState` to keep track of the memory
    /// and registers.
    pub(crate) generation_state: GenerationState<F>,
    // All offsets at which the interpreter execution halts.
    pub(crate) halt_offsets: Vec<usize>,
    /// The interpreter will halt only if the current context matches
    /// halt_context
    pub(crate) halt_context: Option<usize>,
    /// Counts the number of appearances of each opcode. For debugging purposes.
    pub(crate) opcode_count: HashMap<Operation, usize>,
    jumpdest_table: HashMap<usize, BTreeSet<usize>>,
    /// `true` if the we are currently carrying out a jumpdest analysis.
    pub(crate) is_jumpdest_analysis: bool,
    /// Holds the value of the clock: the clock counts the number of operations
    /// in the execution.
    pub(crate) clock: usize,
    /// Log of the maximal number of CPU cycles in one segment execution.
    max_cpu_len_log: Option<usize>,
    /// Optional logs for transactions code.
    pub(crate) struct_logs: Option<Vec<TxZeroStructLogs>>,
    /// Counter within a transaction.
    pub(crate) struct_log_debugger_info: StructLogDebuggerInfo,
}

/// Structure holding necessary information to check the kernel execution
/// against struct logs.
pub(crate) struct StructLogDebuggerInfo {
    /// Opcode counter within a transaction.
    pub(crate) counter: usize,
    /// Gas value in the kernel for a transaction (starting at `GasLimit` and
    /// decreasing with each user opcode).
    pub(crate) gas: u64,
    /// Gas consumed by the previous operation.
    pub(crate) prev_op_gas: u64,
}

/// Simulates the CPU execution from `state` until the program counter reaches
/// `final_label` in the current context.
pub(crate) fn simulate_cpu_and_get_user_jumps<F: RichField>(
    final_label: &str,
    state: &GenerationState<F>,
) -> Option<HashMap<usize, Vec<usize>>> {
    match state.jumpdest_table {
        Some(_) => None,
        None => {
            let halt_pc = KERNEL.global_labels[final_label];
            let initial_context = state.registers.context;
            let mut interpreter = Interpreter::new_with_state_and_halt_condition(
                state,
                halt_pc,
                initial_context,
                None,
                None,
            );

            log::debug!("Simulating CPU for jumpdest analysis.");

            let _ = interpreter.run();

            log::trace!("jumpdest table = {:?}", interpreter.jumpdest_table);

            let clock = interpreter.get_clock();

            interpreter
                .generation_state
                .set_jumpdest_analysis_inputs(interpreter.jumpdest_table);

            log::debug!(
                "Simulated CPU for jumpdest analysis halted after {:?} cycles.",
                clock
            );

            interpreter.generation_state.jumpdest_table
        }
    }
}

/// State data required to initialize the state passed to the prover.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ExtraSegmentData {
    pub(crate) bignum_modmul_result_limbs: Vec<U256>,
    pub(crate) rlp_prover_inputs: Vec<U256>,
    pub(crate) withdrawal_prover_inputs: Vec<U256>,
    pub(crate) ger_prover_inputs: Vec<U256>,
    pub(crate) trie_root_ptrs: TrieRootPtrs,
    pub(crate) jumpdest_table: Option<HashMap<usize, Vec<usize>>>,
    pub(crate) access_lists_ptrs: LinkedListsPtrs,
    pub(crate) state_ptrs: LinkedListsPtrs,
    pub(crate) next_txn_index: usize,
}

pub(crate) fn set_registers_and_run<F: RichField>(
    registers: RegistersState,
    interpreter: &mut Interpreter<F>,
) -> anyhow::Result<(RegistersState, Option<MemoryState>)> {
    interpreter.generation_state.registers = registers;
    interpreter.generation_state.registers.program_counter = KERNEL.global_labels["init"];
    interpreter.generation_state.registers.is_kernel = true;
    interpreter.clock = 0;

    // Write initial registers.
    [
        registers.program_counter.into(),
        (registers.is_kernel as usize).into(),
        registers.stack_len.into(),
        registers.stack_top,
        registers.context.into(),
        registers.gas_used.into(),
    ]
    .iter()
    .enumerate()
    .for_each(|(i, reg_content)| {
        interpreter.generation_state.memory.set(
            MemoryAddress::new(0, Segment::RegistersStates, i),
            *reg_content,
        )
    });

    interpreter.run()
}

impl<F: RichField> Interpreter<F> {
    /// Returns an instance of `Interpreter` given `GenerationInputs`, and
    /// assuming we are initializing with the `KERNEL` code.
    pub(crate) fn new_with_generation_inputs(
        initial_offset: usize,
        initial_stack: Vec<U256>,
        inputs: &GenerationInputs<F>,
        max_cpu_len_log: Option<usize>,
        struct_logs: Option<Vec<TxZeroStructLogs>>,
    ) -> Self {
        debug_inputs(inputs);

        let mut result = Self::new(initial_offset, initial_stack, max_cpu_len_log, struct_logs);
        result.initialize_interpreter_state(inputs);
        result
    }

    pub(crate) fn new(
        initial_offset: usize,
        initial_stack: Vec<U256>,
        max_cpu_len_log: Option<usize>,
        struct_logs: Option<Vec<TxZeroStructLogs>>,
    ) -> Self {
        let mut interpreter = Self {
            generation_state: GenerationState::new(&GenerationInputs::default(), &KERNEL.code)
                .expect("Default inputs are known-good"),
            // `DEFAULT_HALT_OFFSET` is used as a halting point for the interpreter,
            // while the label `halt` is the halting label in the kernel.
            halt_offsets: vec![DEFAULT_HALT_OFFSET, KERNEL.global_labels["halt_final"]],
            halt_context: None,
            opcode_count: HashMap::new(),
            jumpdest_table: HashMap::new(),
            is_jumpdest_analysis: false,
            clock: 0,
            max_cpu_len_log,
            struct_logs: struct_logs.as_ref().map(|struct_log| struct_log.to_vec()),
            struct_log_debugger_info: StructLogDebuggerInfo {
                counter: 0,
                gas: 0,
                prev_op_gas: 0,
            },
        };
        interpreter.generation_state.registers.program_counter = initial_offset;
        let initial_stack_len = initial_stack.len();
        interpreter.generation_state.registers.stack_len = initial_stack_len;
        if !initial_stack.is_empty() {
            interpreter.generation_state.registers.stack_top = initial_stack[initial_stack_len - 1];
            *interpreter.stack_segment_mut() = initial_stack
                .iter()
                .map(|&elt| Some(elt))
                .collect::<Vec<_>>();
        }

        interpreter.initialize_rlp_segment();
        interpreter
    }

    pub(crate) fn new_with_state_and_halt_condition(
        state: &GenerationState<F>,
        halt_offset: usize,
        halt_context: usize,
        max_cpu_len_log: Option<usize>,
        struct_logs: Option<Vec<TxZeroStructLogs>>,
    ) -> Self {
        Self {
            generation_state: state.soft_clone(),
            halt_offsets: vec![halt_offset],
            halt_context: Some(halt_context),
            opcode_count: HashMap::new(),
            jumpdest_table: HashMap::new(),
            is_jumpdest_analysis: true,
            clock: 0,
            max_cpu_len_log,
            struct_logs,
            struct_log_debugger_info: StructLogDebuggerInfo {
                counter: 0,
                gas: 0,
                prev_op_gas: 0,
            },
        }
    }

    /// Initializes the interpreter state given `GenerationInputs`.
    pub(crate) fn initialize_interpreter_state(&mut self, inputs: &GenerationInputs<F>) {
        // Initialize registers.
        let registers_before = RegistersState::new();
        self.generation_state.registers = RegistersState {
            program_counter: self.generation_state.registers.program_counter,
            is_kernel: self.generation_state.registers.is_kernel,
            ..registers_before
        };

        let tries = &inputs.tries;

        // Set state's inputs. We trim unnecessary components.
        self.generation_state.inputs = inputs.trim();

        // Initialize the MPT's pointers.
        let (trie_root_ptrs, state_leaves, storage_leaves, trie_data) =
            load_linked_lists_and_txn_and_receipt_mpts(
                &mut self.generation_state.state_ptrs.accounts,
                &mut self.generation_state.state_ptrs.storage,
                &inputs.tries,
            )
            .expect("Invalid MPT data for preinitialization");

        let trie_roots_after = &inputs.trie_roots_after;
        self.generation_state.trie_root_ptrs = trie_root_ptrs;

        // Initialize the `TrieData` segment.
        let preinit_trie_data_segment = MemorySegmentState { content: trie_data };
        let preinit_accounts_ll_segment = MemorySegmentState {
            content: state_leaves,
        };
        let preinit_storage_ll_segment = MemorySegmentState {
            content: storage_leaves,
        };
        self.insert_preinitialized_segment(Segment::TrieData, preinit_trie_data_segment);
        self.insert_preinitialized_segment(
            Segment::AccountsLinkedList,
            preinit_accounts_ll_segment,
        );
        self.insert_preinitialized_segment(Segment::StorageLinkedList, preinit_storage_ll_segment);

        // Update the RLP and withdrawal prover inputs.
        let rlp_prover_inputs = all_rlp_prover_inputs_reversed(&inputs.signed_txns);
        let withdrawal_prover_inputs = all_withdrawals_prover_inputs_reversed(&inputs.withdrawals);
        let ger_prover_inputs = all_ger_prover_inputs(inputs.ger_data);
        self.generation_state.rlp_prover_inputs = rlp_prover_inputs;
        self.generation_state.withdrawal_prover_inputs = withdrawal_prover_inputs;
        self.generation_state.ger_prover_inputs = ger_prover_inputs;

        // Set `GlobalMetadata` values.
        let metadata = &inputs.block_metadata;
        let global_metadata_to_set = [
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
            #[cfg(feature = "eth_mainnet")]
            (
                GlobalMetadata::BlockBlobGasUsed,
                metadata.block_blob_gas_used,
            ),
            #[cfg(feature = "eth_mainnet")]
            (
                GlobalMetadata::BlockExcessBlobGas,
                metadata.block_excess_blob_gas,
            ),
            #[cfg(feature = "eth_mainnet")]
            (
                GlobalMetadata::ParentBeaconBlockRoot,
                h2u(metadata.parent_beacon_block_root),
            ),
            (GlobalMetadata::BlockGasUsedBefore, inputs.gas_used_before),
            (GlobalMetadata::BlockGasUsedAfter, inputs.gas_used_after),
            (GlobalMetadata::TxnNumberBefore, inputs.txn_number_before),
            (
                GlobalMetadata::TxnNumberAfter,
                inputs.txn_number_before + inputs.signed_txns.len(),
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
            #[cfg(feature = "cdk_erigon")]
            (
                GlobalMetadata::BurnAddr,
                inputs
                    .burn_addr
                    .map_or_else(U256::max_value, |addr| U256::from_big_endian(&addr.0)),
            ),
        ];

        self.set_global_metadata_multi_fields(&global_metadata_to_set);

        // Set final block bloom values.
        let final_block_bloom_fields = (0..8)
            .map(|i| {
                (
                    MemoryAddress::new(0, Segment::GlobalBlockBloom, i),
                    metadata.block_bloom[i],
                )
            })
            .collect::<Vec<_>>();

        self.set_memory_multi_addresses(&final_block_bloom_fields);

        // Set previous block hash.
        let block_hashes_fields = (0..256)
            .map(|i| {
                (
                    MemoryAddress::new(0, Segment::BlockHashes, i),
                    h2u(inputs.block_hashes.prev_hashes[i]),
                )
            })
            .collect::<Vec<_>>();

        self.set_memory_multi_addresses(&block_hashes_fields);

        // Write initial registers.
        let registers_before = [
            registers_before.program_counter.into(),
            (registers_before.is_kernel as usize).into(),
            registers_before.stack_len.into(),
            registers_before.stack_top,
            registers_before.context.into(),
            registers_before.gas_used.into(),
        ];
        let registers_before_fields = (0..registers_before.len())
            .map(|i| {
                (
                    MemoryAddress::new(0, Segment::RegistersStates, i),
                    registers_before[i],
                )
            })
            .collect::<Vec<_>>();

        self.set_memory_multi_addresses(&registers_before_fields);
    }

    /// Applies all memory operations since the last checkpoint. The memory
    /// operations are cleared at each checkpoint.
    pub(crate) fn apply_memops(&mut self) -> Result<(), anyhow::Error> {
        for memop in &self.generation_state.traces.memory_ops {
            let &MemoryOp {
                kind,
                address,
                value,
                ..
            } = memop;
            match kind {
                MemoryOpKind::Read => {
                    if self.generation_state.memory.get(address).is_none() {
                        if !self.is_preinitialized_segment(address.segment) && !value.is_zero() {
                            return Err(anyhow!("The initial value {:?} at address {:?} should be zero, because it is not preinitialized.", value, address));
                        }
                        self.generation_state.memory.set(address, value);
                    }
                }
                MemoryOpKind::Write => self.generation_state.memory.set(address, value),
            }
        }

        Ok(())
    }

    pub(crate) fn run(&mut self) -> Result<(RegistersState, Option<MemoryState>), anyhow::Error> {
        self.run_cpu(self.max_cpu_len_log)
    }

    /// Returns the max number of CPU cycles.
    pub(crate) const fn get_max_cpu_len_log(&self) -> Option<usize> {
        self.max_cpu_len_log
    }

    pub(crate) fn reset_opcode_counts(&mut self) {
        self.opcode_count = HashMap::new();
    }

    pub(crate) fn code(&self) -> &MemorySegmentState {
        // The context is 0 if we are in kernel mode.
        &self.generation_state.memory.contexts[(1 - self.is_kernel() as usize) * self.context()]
            .segments[Segment::Code.unscale()]
    }

    pub(crate) fn set_global_metadata_multi_fields(&mut self, metadata: &[(GlobalMetadata, U256)]) {
        for &(field, value) in metadata {
            let field = field.unscale();
            self.generation_state.memory.contexts[0].segments[Segment::GlobalMetadata.unscale()]
                .set(field, value);
        }
    }

    pub(crate) fn set_memory_multi_addresses(&mut self, addrs: &[(MemoryAddress, U256)]) {
        for &(addr, val) in addrs {
            self.generation_state.memory.set(addr, val);
        }
    }

    // As this relies on the underlying `GenerationState` method, stacks containing
    // more than 10 elements will be truncated. As such, new tests that would need
    // to access more elements would require special handling.
    pub(crate) fn stack(&self) -> Vec<U256> {
        let mut stack = self.generation_state.stack();
        stack.reverse();

        stack
    }

    fn stack_segment_mut(&mut self) -> &mut Vec<Option<U256>> {
        let context = self.context();
        &mut self.generation_state.memory.contexts[context].segments[Segment::Stack.unscale()]
            .content
    }

    pub(crate) fn add_jumpdest_offset(&mut self, offset: usize) {
        if let Some(jumpdest_table) = self
            .jumpdest_table
            .get_mut(&self.generation_state.registers.context)
        {
            jumpdest_table.insert(offset);
        } else {
            self.jumpdest_table.insert(
                self.generation_state.registers.context,
                BTreeSet::from([offset]),
            );
        }
    }

    pub(crate) const fn is_kernel(&self) -> bool {
        self.generation_state.registers.is_kernel
    }

    pub(crate) const fn context(&self) -> usize {
        self.generation_state.registers.context
    }

    /// Writes the encoding of 0 at @ENCODED_EMPTY_NODE_ADDR.
    pub(crate) fn initialize_rlp_segment(&mut self) {
        self.generation_state
            .memory
            .set(MemoryAddress::new(0, Segment::RlpRaw, 0), 0x80.into())
    }

    /// Inserts a preinitialized segment, given as a [Segment],
    /// into the `preinitialized_segments` memory field.
    fn insert_preinitialized_segment(&mut self, segment: Segment, values: MemorySegmentState) {
        self.generation_state
            .memory
            .insert_preinitialized_segment(segment, values);
    }

    pub(crate) fn is_preinitialized_segment(&self, segment: usize) -> bool {
        self.generation_state
            .memory
            .is_preinitialized_segment(segment)
    }
}

impl<F: RichField> State<F> for Interpreter<F> {
    /// Returns a `GenerationStateCheckpoint` to save the current registers and
    /// reset memory operations to the empty vector.
    fn checkpoint(&mut self) -> GenerationStateCheckpoint {
        self.generation_state.traces.memory_ops = vec![];
        GenerationStateCheckpoint {
            registers: self.generation_state.registers,
            traces: self.generation_state.traces.checkpoint(),
            clock: self.get_clock(),
        }
    }

    fn check_against_struct_logs_before_op(
        &mut self,
        opcode: u8,
        to_check: bool,
    ) -> Result<(), ProgramError> {
        if let Some(struct_logs) = &self.struct_logs
            && to_check
        {
            let txn_idx = self.generation_state.next_txn_index;

            if let Some(txn_struct_logs) = &struct_logs[txn_idx - 1] {
                let counter = self.struct_log_debugger_info.counter;
                if counter == 0 {
                    // Initialize txn gas.
                    let gas_limit_address = MemoryAddress::new(
                        self.get_registers().context,
                        Segment::ContextMetadata,
                        ContextMetadata::GasLimit.unscale(), // context offsets are already scaled
                    );
                    let gas_limit = self.generation_state.get_from_memory(gas_limit_address);
                    self.struct_log_debugger_info.gas = gas_limit.low_u64();
                    // Check against actual initial gas.
                    if gas_limit.low_u64() != txn_struct_logs[0].gas {
                        log::warn!(
                            "Wrong Initial txn gas: expected {:?}, got {:?}.",
                            txn_struct_logs[0].gas,
                            gas_limit.as_u64()
                        );
                        return Err(ProgramError::StructLogDebuggerError);
                    }
                }

                // Check opcode.
                let cur_txn_struct_logs = &txn_struct_logs[counter];
                let struct_op = cur_txn_struct_logs.op.as_str();
                let op_string_res = get_mnemonic(opcode);
                match op_string_res {
                    Ok(cur_op_str) => {
                        let cur_op = cur_op_str.to_string();
                        if struct_op != cur_op {
                            log::warn!("Wrong opcode: expected {struct_op}, got {cur_op}.");
                            return Err(ProgramError::StructLogDebuggerError);
                        }
                    }
                    Err(_) => {
                        // Update the counter since we will not get to the next
                        // check.
                        self.struct_log_debugger_info.counter += 1;
                        if self.struct_log_debugger_info.counter == txn_struct_logs.len() {
                            self.struct_log_debugger_info.counter = 0;
                        }
                        if struct_op != "INVALID" {
                            return Err(ProgramError::StructLogDebuggerError);
                        }
                    }
                }

                // Check pc.
                let txn_pc = cur_txn_struct_logs.pc;
                if txn_pc != self.get_registers().program_counter as u64 {
                    log::warn!(
                        "Wrong pc: expected {} but got {}.",
                        txn_pc,
                        self.get_registers().program_counter
                    );
                    return Err(ProgramError::StructLogDebuggerError);
                }

                // Check stack.
                if let Some(txn_stack) = &cur_txn_struct_logs.stack {
                    let cur_stack = self.get_full_stack();
                    if !cur_stack
                        .iter()
                        .copied()
                        .eq(txn_stack.iter().map(|s| U256(*s.as_limbs())))
                    {
                        log::warn!(
                            "Wrong stack: expected {:?} but got {:?}.",
                            txn_stack,
                            cur_stack
                        );
                        return Err(ProgramError::StructLogDebuggerError);
                    }
                };
            };
        }
        Ok(())
    }

    fn check_against_struct_logs_after_op(
        &mut self,
        res: &Result<Operation, ProgramError>,
        consumed_gas: u64,
        to_check: bool,
    ) -> Result<(), ProgramError> {
        if let Some(struct_logs) = &self.struct_logs
            && to_check
        {
            let txn_idx = self.generation_state.next_txn_index;
            // First, update the gas.
            self.struct_log_debugger_info.gas -= self.struct_log_debugger_info.prev_op_gas;
            self.struct_log_debugger_info.prev_op_gas = consumed_gas;

            if let Some(txn_struct_logs) = &struct_logs[txn_idx - 1] {
                // If the transaction errors, we simply log a warning, since struct logs do not
                // actually return an error in that case.
                let cur_txn_struct_logs = &txn_struct_logs[self.struct_log_debugger_info.counter];

                if res.is_err() {
                    log::warn!("Kernel execution errored with: {:?}.", res);
                }

                // Check opcode gas.
                let txn_op_gas = self.struct_log_debugger_info.gas;
                if txn_op_gas != cur_txn_struct_logs.gas {
                    log::warn!(
                        "Wrong gas update in the last operation: expected {} but got {}.",
                        cur_txn_struct_logs.gas,
                        txn_op_gas
                    );
                    return Err(ProgramError::StructLogDebuggerError);
                }

                // Update the user code counter.
                self.struct_log_debugger_info.counter += 1;
                if self.struct_log_debugger_info.counter == txn_struct_logs.len() {
                    self.struct_log_debugger_info.counter = 0;
                }
            }
        }
        Ok(())
    }

    fn update_struct_logs_gas(&mut self, n: u64) {
        self.struct_log_debugger_info.gas = n;
    }

    fn incr_gas(&mut self, n: u64) {
        self.generation_state.incr_gas(n);
    }

    fn incr_pc(&mut self, n: usize) {
        self.generation_state.incr_pc(n);
    }

    fn is_kernel(&self) -> bool {
        self.is_kernel()
    }

    fn get_registers(&self) -> RegistersState {
        self.generation_state.get_registers()
    }

    fn get_mut_registers(&mut self) -> &mut RegistersState {
        self.generation_state.get_mut_registers()
    }

    fn get_from_memory(&mut self, address: MemoryAddress) -> U256 {
        self.generation_state.memory.get_with_init(address)
    }

    fn get_generation_state(&self) -> &GenerationState<F> {
        &self.generation_state
    }

    fn get_mut_generation_state(&mut self) -> &mut GenerationState<F> {
        &mut self.generation_state
    }

    fn get_clock(&self) -> usize {
        self.clock
    }

    fn push_cpu(&mut self, _val: CpuColumnsView<F>) {
        // We don't push anything, but increment the clock to match
        // an actual proof generation.
        self.clock += 1;
    }

    fn push_logic(&mut self, _op: logic::Operation) {}

    fn push_arithmetic(&mut self, _op: arithmetic::Operation) {}

    fn push_byte_packing(&mut self, _op: BytePackingOp) {}

    fn push_keccak(&mut self, _input: [u64; keccak::keccak_stark::NUM_INPUTS], _clock: usize) {}

    fn push_keccak_bytes(&mut self, _input: [u8; KECCAK_WIDTH_BYTES], _clock: usize) {}

    fn push_keccak_sponge(&mut self, _op: KeccakSpongeOp) {}

    fn rollback(&mut self, checkpoint: GenerationStateCheckpoint) {
        self.clock = checkpoint.clock;
        self.generation_state.rollback(checkpoint)
    }

    fn get_context(&self) -> usize {
        self.context()
    }

    fn get_halt_context(&self) -> Option<usize> {
        self.halt_context
    }

    fn mem_get_kernel_content(&self) -> Vec<Option<U256>> {
        self.generation_state.memory.contexts[0].segments[Segment::KernelGeneral.unscale()]
            .content
            .clone()
    }

    fn apply_ops(&mut self, _checkpoint: GenerationStateCheckpoint) {
        self.apply_memops()
            .expect("We should not have nonzero initial values in non-preinitialized segments");
    }

    fn get_stack(&self) -> Vec<U256> {
        let mut stack = self.stack();
        stack.reverse();

        stack
    }

    fn get_full_stack(&self) -> Vec<U256> {
        let mut stack: Vec<U256> = (0..self.get_registers().stack_len)
            .map(|i| crate::witness::util::stack_peek(self.get_generation_state(), i).unwrap())
            .collect();
        stack.reverse();

        stack
    }

    fn get_halt_offsets(&self) -> Vec<usize> {
        self.halt_offsets.clone()
    }

    fn get_active_memory(&self) -> Option<MemoryState> {
        let mut memory_state = MemoryState {
            contexts: vec![
                MemoryContextState::default();
                self.generation_state.memory.contexts.len()
            ],
            ..self.generation_state.memory.clone()
        };

        // Only copy memory from non-stale contexts
        for (ctx_idx, ctx) in self.generation_state.memory.contexts.iter().enumerate() {
            if !self
                .get_generation_state()
                .stale_contexts
                .contains(&ctx_idx)
            {
                memory_state.contexts[ctx_idx] = ctx.clone();
            }
        }

        memory_state.preinitialized_segments =
            self.generation_state.memory.preinitialized_segments.clone();

        Some(memory_state)
    }

    fn update_interpreter_final_registers(&mut self, final_registers: RegistersState) {
        {
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
            self.set_memory_multi_addresses(&registers_after_fields);
        }
    }

    fn try_perform_instruction(&mut self) -> Result<Operation, ProgramError> {
        let registers = self.generation_state.registers;
        let (mut row, opcode) = self.base_row();

        let is_user_mode = !self.is_kernel();

        // If we are in user and debug mode, and have extracted the struct logs, check
        // the kernel run against the struct logs.
        let to_check = is_user_mode
            && (self.get_registers().program_counter != 0 || opcode != 0x00)
            && !self.is_jumpdest_analysis;
        self.check_against_struct_logs_before_op(opcode, to_check)?;

        let op = decode(registers, opcode)?;

        // Increment the opcode count
        *self.opcode_count.entry(op).or_insert(0) += 1;

        fill_op_flag(op, &mut row);

        self.fill_stack_fields(&mut row)?;

        if registers.is_kernel {
            log_kernel_instruction(self, op);
        } else {
            self.log_debug(format!("User instruction: {:?}", op));
        }

        let generation_state = self.get_mut_generation_state();
        // Might write in general CPU columns when it shouldn't, but the correct values
        // will overwrite these ones during the op generation.
        if let Some(special_len) = get_op_special_length(op) {
            if generation_state.stack().len() != special_len {
                // If the `State` is an interpreter, we cannot rely on the row to carry out the
                // check.
                generation_state.registers.is_stack_top_read = true;
            }
        } else if let Some(inv) = row.stack_len.try_inverse() {
            row.general.stack_mut().stack_inv = inv;
            row.general.stack_mut().stack_inv_aux = F::ONE;
        }

        let res_and_gas = self.perform_state_op(op, row);
        let (res, consumed_gas) = match res_and_gas {
            Ok((res, consumed_gas)) => (Ok(res), consumed_gas),
            Err(e) => (Err(e), 0),
        };

        // Final checks against struct logs in debug and user mode.
        self.check_against_struct_logs_after_op(&res, consumed_gas, to_check)?;
        res
    }

    fn log_debug(&self, msg: String) {
        if !self.is_jumpdest_analysis {
            log::debug!("{}", msg);
        }
    }

    fn log(&self, level: Level, msg: String) {
        if !self.is_jumpdest_analysis {
            log::log!(level, "{}", msg);
        }
    }
}

impl<F: RichField> Transition<F> for Interpreter<F> {
    fn generate_jumpdest_analysis(&mut self, dst: usize) -> bool {
        if self.is_jumpdest_analysis && !self.generation_state.registers.is_kernel {
            self.add_jumpdest_offset(dst);
            true
        } else {
            false
        }
    }

    fn skip_if_necessary(&mut self, op: Operation) -> Result<Operation, ProgramError> {
        if self.is_kernel()
            && self.is_jumpdest_analysis
            && self.generation_state.registers.program_counter
                == KERNEL.global_labels["jumpdest_analysis"]
        {
            self.generation_state.registers.program_counter =
                KERNEL.global_labels["jumpdest_analysis_end"];
            self.generation_state
                .set_jumpdest_bits(&self.generation_state.get_current_code()?);
            let opcode = self
                .code()
                .get(self.generation_state.registers.program_counter)
                .byte(0);

            decode(self.generation_state.registers, opcode)
        } else {
            Ok(op)
        }
    }

    fn fill_stack_fields(
        &mut self,
        _row: &mut crate::cpu::columns::CpuColumnsView<F>,
    ) -> Result<(), ProgramError> {
        self.generation_state.registers.is_stack_top_read = false;
        self.generation_state.registers.check_overflow = false;

        Ok(())
    }
}

fn get_mnemonic(opcode: u8) -> anyhow::Result<&'static str> {
    match opcode {
        0x00 => Ok("STOP"),
        0x01 => Ok("ADD"),
        0x02 => Ok("MUL"),
        0x03 => Ok("SUB"),
        0x04 => Ok("DIV"),
        0x05 => Ok("SDIV"),
        0x06 => Ok("MOD"),
        0x07 => Ok("SMOD"),
        0x08 => Ok("ADDMOD"),
        0x09 => Ok("MULMOD"),
        0x0a => Ok("EXP"),
        0x0b => Ok("SIGNEXTEND"),
        0x0c => Ok("ADDFP254"),
        0x0d => Ok("MULFP254"),
        0x0e => Ok("SUBFP254"),
        0x0f => Ok("SUBMOD"),
        0x10 => Ok("LT"),
        0x11 => Ok("GT"),
        0x12 => Ok("SLT"),
        0x13 => Ok("SGT"),
        0x14 => Ok("EQ"),
        0x15 => Ok("ISZERO"),
        0x16 => Ok("AND"),
        0x17 => Ok("OR"),
        0x18 => Ok("XOR"),
        0x19 => Ok("NOT"),
        0x1a => Ok("BYTE"),
        0x1b => Ok("SHL"),
        0x1c => Ok("SHR"),
        0x1d => Ok("SAR"),
        0x20 => Ok("KECCAK256"),
        0x21 => Ok("KECCAK_GENERAL"),
        #[cfg(feature = "cdk_erigon")]
        0x22 => Ok("POSEIDON"),
        #[cfg(feature = "cdk_erigon")]
        0x23 => Ok("POSEIDON_GENERAL"),
        0x30 => Ok("ADDRESS"),
        0x31 => Ok("BALANCE"),
        0x32 => Ok("ORIGIN"),
        0x33 => Ok("CALLER"),
        0x34 => Ok("CALLVALUE"),
        0x35 => Ok("CALLDATALOAD"),
        0x36 => Ok("CALLDATASIZE"),
        0x37 => Ok("CALLDATACOPY"),
        0x38 => Ok("CODESIZE"),
        0x39 => Ok("CODECOPY"),
        0x3a => Ok("GASPRICE"),
        0x3b => Ok("EXTCODESIZE"),
        0x3c => Ok("EXTCODECOPY"),
        0x3d => Ok("RETURNDATASIZE"),
        0x3e => Ok("RETURNDATACOPY"),
        0x3f => Ok("EXTCODEHASH"),
        0x40 => Ok("BLOCKHASH"),
        0x41 => Ok("COINBASE"),
        0x42 => Ok("TIMESTAMP"),
        0x43 => Ok("NUMBER"),
        0x44 => Ok("DIFFICULTY"),
        0x45 => Ok("GASLIMIT"),
        0x46 => Ok("CHAINID"),
        0x47 => Ok("SELFBALANCE"),
        0x48 => Ok("BASEFEE"),
        #[cfg(feature = "eth_mainnet")]
        0x49 => Ok("BLOBHASH"),
        #[cfg(feature = "eth_mainnet")]
        0x4a => Ok("BLOBBASEFEE"),
        0x50 => Ok("POP"),
        0x51 => Ok("MLOAD"),
        0x52 => Ok("MSTORE"),
        0x53 => Ok("MSTORE8"),
        0x54 => Ok("SLOAD"),
        0x55 => Ok("SSTORE"),
        0x56 => Ok("JUMP"),
        0x57 => Ok("JUMPI"),
        0x58 => Ok("PC"),
        0x59 => Ok("MSIZE"),
        0x5a => Ok("GAS"),
        0x5b => Ok("JUMPDEST"),
        0x5c => Ok("TLOAD"),
        0x5d => Ok("TSTORE"),
        0x5e => Ok("MCOPY"),
        0x5f => Ok("PUSH0"),
        0x60 => Ok("PUSH1"),
        0x61 => Ok("PUSH2"),
        0x62 => Ok("PUSH3"),
        0x63 => Ok("PUSH4"),
        0x64 => Ok("PUSH5"),
        0x65 => Ok("PUSH6"),
        0x66 => Ok("PUSH7"),
        0x67 => Ok("PUSH8"),
        0x68 => Ok("PUSH9"),
        0x69 => Ok("PUSH10"),
        0x6a => Ok("PUSH11"),
        0x6b => Ok("PUSH12"),
        0x6c => Ok("PUSH13"),
        0x6d => Ok("PUSH14"),
        0x6e => Ok("PUSH15"),
        0x6f => Ok("PUSH16"),
        0x70 => Ok("PUSH17"),
        0x71 => Ok("PUSH18"),
        0x72 => Ok("PUSH19"),
        0x73 => Ok("PUSH20"),
        0x74 => Ok("PUSH21"),
        0x75 => Ok("PUSH22"),
        0x76 => Ok("PUSH23"),
        0x77 => Ok("PUSH24"),
        0x78 => Ok("PUSH25"),
        0x79 => Ok("PUSH26"),
        0x7a => Ok("PUSH27"),
        0x7b => Ok("PUSH28"),
        0x7c => Ok("PUSH29"),
        0x7d => Ok("PUSH30"),
        0x7e => Ok("PUSH31"),
        0x7f => Ok("PUSH32"),
        0x80 => Ok("DUP1"),
        0x81 => Ok("DUP2"),
        0x82 => Ok("DUP3"),
        0x83 => Ok("DUP4"),
        0x84 => Ok("DUP5"),
        0x85 => Ok("DUP6"),
        0x86 => Ok("DUP7"),
        0x87 => Ok("DUP8"),
        0x88 => Ok("DUP9"),
        0x89 => Ok("DUP10"),
        0x8a => Ok("DUP11"),
        0x8b => Ok("DUP12"),
        0x8c => Ok("DUP13"),
        0x8d => Ok("DUP14"),
        0x8e => Ok("DUP15"),
        0x8f => Ok("DUP16"),
        0x90 => Ok("SWAP1"),
        0x91 => Ok("SWAP2"),
        0x92 => Ok("SWAP3"),
        0x93 => Ok("SWAP4"),
        0x94 => Ok("SWAP5"),
        0x95 => Ok("SWAP6"),
        0x96 => Ok("SWAP7"),
        0x97 => Ok("SWAP8"),
        0x98 => Ok("SWAP9"),
        0x99 => Ok("SWAP10"),
        0x9a => Ok("SWAP11"),
        0x9b => Ok("SWAP12"),
        0x9c => Ok("SWAP13"),
        0x9d => Ok("SWAP14"),
        0x9e => Ok("SWAP15"),
        0x9f => Ok("SWAP16"),
        0xa0 => Ok("LOG0"),
        0xa1 => Ok("LOG1"),
        0xa2 => Ok("LOG2"),
        0xa3 => Ok("LOG3"),
        0xa4 => Ok("LOG4"),
        0xa5 => Ok("PANIC"),
        0xc0 => Ok("MSTORE_32BYTES_1"),
        0xc1 => Ok("MSTORE_32BYTES_2"),
        0xc2 => Ok("MSTORE_32BYTES_3"),
        0xc3 => Ok("MSTORE_32BYTES_4"),
        0xc4 => Ok("MSTORE_32BYTES_5"),
        0xc5 => Ok("MSTORE_32BYTES_6"),
        0xc6 => Ok("MSTORE_32BYTES_7"),
        0xc7 => Ok("MSTORE_32BYTES_8"),
        0xc8 => Ok("MSTORE_32BYTES_9"),
        0xc9 => Ok("MSTORE_32BYTES_10"),
        0xca => Ok("MSTORE_32BYTES_11"),
        0xcb => Ok("MSTORE_32BYTES_12"),
        0xcc => Ok("MSTORE_32BYTES_13"),
        0xcd => Ok("MSTORE_32BYTES_14"),
        0xce => Ok("MSTORE_32BYTES_15"),
        0xcf => Ok("MSTORE_32BYTES_16"),
        0xd0 => Ok("MSTORE_32BYTES_17"),
        0xd1 => Ok("MSTORE_32BYTES_18"),
        0xd2 => Ok("MSTORE_32BYTES_19"),
        0xd3 => Ok("MSTORE_32BYTES_20"),
        0xd4 => Ok("MSTORE_32BYTES_21"),
        0xd5 => Ok("MSTORE_32BYTES_22"),
        0xd6 => Ok("MSTORE_32BYTES_23"),
        0xd7 => Ok("MSTORE_32BYTES_24"),
        0xd8 => Ok("MSTORE_32BYTES_25"),
        0xd9 => Ok("MSTORE_32BYTES_26"),
        0xda => Ok("MSTORE_32BYTES_27"),
        0xdb => Ok("MSTORE_32BYTES_28"),
        0xdc => Ok("MSTORE_32BYTES_29"),
        0xdd => Ok("MSTORE_32BYTES_30"),
        0xde => Ok("MSTORE_32BYTES_31"),
        0xdf => Ok("MSTORE_32BYTES_32"),
        0xee => Ok("PROVER_INPUT"),
        0xf0 => Ok("CREATE"),
        0xf1 => Ok("CALL"),
        0xf2 => Ok("CALLCODE"),
        0xf3 => Ok("RETURN"),
        0xf4 => Ok("DELEGATECALL"),
        0xf5 => Ok("CREATE2"),
        0xf6 => Ok("GET_CONTEXT"),
        0xf7 => Ok("SET_CONTEXT"),
        0xf8 => Ok("MLOAD_32BYTES"),
        0xf9 => Ok("EXIT_KERNEL"),
        0xfa => Ok("STATICCALL"),
        0xfb => Ok("MLOAD_GENERAL"),
        0xfc => Ok("MSTORE_GENERAL"),
        0xfd => Ok("REVERT"),
        0xff => Ok("SELFDESTRUCT"),
        _ => Err(anyhow!("Invalid opcode: {}", opcode)),
    }
}

#[cfg(test)]
mod tests {
    use ethereum_types::U256;
    use plonky2::field::goldilocks_field::GoldilocksField as F;

    use crate::cpu::kernel::constants::context_metadata::ContextMetadata;
    use crate::cpu::kernel::interpreter::Interpreter;
    use crate::memory::segments::Segment;
    use crate::witness::memory::MemoryAddress;
    use crate::witness::operation::CONTEXT_SCALING_FACTOR;

    #[test]
    fn test_run_with_memory() -> anyhow::Result<()> {
        //         PUSH1 0xff
        //         PUSH1 0
        //         MSTORE

        //         PUSH1 0
        //         MLOAD

        //         PUSH1 1
        //         MLOAD

        //         PUSH1 0x42
        //         PUSH1 0x27
        //         MSTORE8
        let code = [
            0x60, 0xff, 0x60, 0x0, 0x52, 0x60, 0, 0x51, 0x60, 0x1, 0x51, 0x60, 0x42, 0x60, 0x27,
            0x53,
        ];
        let mut interpreter: Interpreter<F> = Interpreter::new(0, vec![], None, None);

        interpreter.set_code(1, code.to_vec());

        interpreter.generation_state.memory.contexts[1].segments
            [Segment::ContextMetadata.unscale()]
        .set(ContextMetadata::GasLimit.unscale(), 100_000.into());
        // Set context and kernel mode.
        interpreter.set_context(1);
        interpreter.set_is_kernel(false);
        // Set memory necessary to sys_stop.
        interpreter.generation_state.memory.set(
            MemoryAddress::new(
                1,
                Segment::ContextMetadata,
                ContextMetadata::ParentProgramCounter.unscale(),
            ),
            0xdeadbeefu32.into(),
        );
        interpreter.generation_state.memory.set(
            MemoryAddress::new(
                1,
                Segment::ContextMetadata,
                ContextMetadata::ParentContext.unscale(),
            ),
            U256::one() << CONTEXT_SCALING_FACTOR,
        );

        interpreter.run()?;

        // sys_stop returns `success` and `cum_gas_used`, that we need to pop.
        interpreter.pop().expect("Stack should not be empty");
        interpreter.pop().expect("Stack should not be empty");

        assert_eq!(interpreter.stack(), &[0xff.into(), 0xff00.into()]);
        assert_eq!(
            interpreter.generation_state.memory.contexts[1].segments[Segment::MainMemory.unscale()]
                .get(0x27),
            0x42.into()
        );
        assert_eq!(
            interpreter.generation_state.memory.contexts[1].segments[Segment::MainMemory.unscale()]
                .get(0x1f),
            0xff.into()
        );
        Ok(())
    }
}
